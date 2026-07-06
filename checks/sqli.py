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
        self.error_signatures.extend(["SQLITE_ERROR", "SequelizeDatabaseError"])
        self.common_parameters = ["id", "q", "search", "query", "user", "email"]

    def execute(self, http_client: HttpClient, target_url: str):
        findings = []
        for param in self.common_parameters:
            for payload in self.payloads:
                try:
                    parsed_url = urlparse(target_url)
                    query_params = parse_qs(parsed_url.query)
                    query_params[param] = [payload]
                    new_query = urlencode(query_params, doseq=True)
                    test_url = urlunparse(parsed_url._replace(query=new_query))

                    response = http_client.request(Method.GET, path=test_url)
                    
                    found = next((signature for signature in self.error_signatures if signature in response.body), None)
                    if found:
                        findings.append(RawFinding(
                            vuln_id="INJ-SQLI-ERROR-BASED",
                            endpoint= test_url,
                            evidence=Evidence(
                                request=f"GET {test_url}",
                                response=found,
                                parameters=[param],
                            )
                        ))
                        # Stop fuzzing payloads for this parameter if we already found an injection
                        break

                except Exception as e:
                    logging.error(f"Error: {e} on payload: {payload}")

        return findings
"""
Drop-in replacement for cs50.SQL using Python's built-in sqlite3.
Supports the same interface: db.execute(query, *args) with ? placeholders.
"""

import sqlite3


class SQL:
    def __init__(self, url):
        # cs50 uses "sqlite:///path" — strip the prefix
        if url.startswith("sqlite:////"):
            path = url[len("sqlite:////"):]
        elif url.startswith("sqlite:///"):
            path = url[len("sqlite:///"):]
        else:
            path = url

        self._path = path

    def _get_connection(self):
        conn = sqlite3.connect(self._path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def execute(self, query, *args, **kwargs):
        """
        Execute a SQL query.

        For SELECT: returns a list of dicts.
        For INSERT: returns the last inserted row id.
        For UPDATE/DELETE/CREATE/PRAGMA: returns the number of affected rows.

        Supports positional ? params passed as *args,
        and :name params passed as kwargs (e.g. username="foo").
        """
        conn = self._get_connection()
        try:
            # Handle cs50-style :name params passed as keyword args
            # e.g. db.execute("... WHERE username = :username", username="foo")
            if kwargs:
                params = kwargs
            elif args and isinstance(args[0], dict):
                params = args[0]
            else:
                params = args

            cursor = conn.execute(query, params)

            query_stripped = query.strip().upper()
            if query_stripped.startswith("SELECT"):
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
            elif query_stripped.startswith("INSERT"):
                conn.commit()
                return cursor.lastrowid
            else:
                conn.commit()
                return cursor.rowcount
        finally:
            conn.close()

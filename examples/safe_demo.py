import sqlite3

def get_user_profile(user_id: int):
    """
    Hàm truy vấn thông tin người dùng an toàn.
    Sử dụng tham số hóa (Parameterized Query) thay vì nối chuỗi trực tiếp.
    """
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # Tham số hóa an toàn chống SQL Injection (CWE-89)
    cursor.execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user

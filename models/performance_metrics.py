import sqlite3
from datetime import datetime

def init_performance_db():
    conn = sqlite3.connect('database/users.db')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS performance_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            video_id INTEGER,
            file_size_mb REAL,
            encryption_time_ms INTEGER,
            cpu_usage_percent REAL,
            memory_usage_mb REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            operation_type TEXT,
            FOREIGN KEY(video_id) REFERENCES videos(id)
        )
    ''')
    conn.commit()
    conn.close()

def save_metrics(user_id, video_id, file_size_mb, encryption_time_ms, cpu_usage_percent, memory_usage_mb, operation_type):
    conn = sqlite3.connect('database/users.db')
    conn.execute('''
        INSERT INTO performance_metrics 
        (user_id, video_id, file_size_mb, encryption_time_ms, cpu_usage_percent, memory_usage_mb, operation_type)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, video_id, file_size_mb, encryption_time_ms, cpu_usage_percent, memory_usage_mb, operation_type))
    conn.commit()
    conn.close()

def get_performance_stats(user_id=None):
    conn = sqlite3.connect('database/users.db')
    cursor = conn.cursor()
    
    if user_id:
        cursor.execute('''
            SELECT 
                CASE 
                    WHEN file_size_mb < 10 THEN '0-10 MB'
                    WHEN file_size_mb < 50 THEN '10-50 MB'
                    WHEN file_size_mb < 100 THEN '50-100 MB'
                    ELSE '100+ MB'
                END as size_range,
                AVG(encryption_time_ms) as avg_time,
                AVG(cpu_usage_percent) as avg_cpu,
                AVG(memory_usage_mb) as avg_memory,
                COUNT(*) as count,
                operation_type
            FROM performance_metrics
            WHERE user_id = ?
            GROUP BY size_range, operation_type
            ORDER BY 
                operation_type,
                CASE size_range
                    WHEN '0-10 MB' THEN 1
                    WHEN '10-50 MB' THEN 2
                    WHEN '50-100 MB' THEN 3
                    ELSE 4
                END
        ''', (user_id,))
    else:
        cursor.execute('''
            SELECT 
                CASE 
                    WHEN file_size_mb < 10 THEN '0-10 MB'
                    WHEN file_size_mb < 50 THEN '10-50 MB'
                    WHEN file_size_mb < 100 THEN '50-100 MB'
                    ELSE '100+ MB'
                END as size_range,
                AVG(encryption_time_ms) as avg_time,
                AVG(cpu_usage_percent) as avg_cpu,
                AVG(memory_usage_mb) as avg_memory,
                COUNT(*) as count,
                operation_type
            FROM performance_metrics
            GROUP BY size_range, operation_type
            ORDER BY 
                operation_type,
                CASE size_range
                    WHEN '0-10 MB' THEN 1
                    WHEN '10-50 MB' THEN 2
                    WHEN '50-100 MB' THEN 3
                    ELSE 4
                END
        ''')
    stats_by_size = cursor.fetchall()

    # Get recent performance metrics
    if user_id:
        cursor.execute('''
            SELECT 
                file_size_mb,
                encryption_time_ms,
                cpu_usage_percent,
                memory_usage_mb,
                timestamp,
                operation_type
            FROM performance_metrics
            WHERE user_id = ?
            ORDER BY timestamp DESC
            LIMIT 10
        ''', (user_id,))
    else:
        cursor.execute('''
            SELECT 
                file_size_mb,
                encryption_time_ms,
                cpu_usage_percent,
                memory_usage_mb,
                timestamp,
                operation_type
            FROM performance_metrics
            ORDER BY timestamp DESC
            LIMIT 10
        ''')
    recent_metrics = cursor.fetchall()

    conn.close()
    return stats_by_size, recent_metrics 
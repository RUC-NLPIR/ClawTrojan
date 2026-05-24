#!/usr/bin/env python3
"""共享工具函数"""

import hashlib


def calculate_hash(file_path, algorithm='blake2b', chunk_size=8192):
    """计算文件哈希值"""
    if algorithm == 'blake2b':
        hasher = hashlib.blake2b(digest_size=32)
    elif algorithm == 'md5':
        hasher = hashlib.md5()
    elif algorithm == 'sha256':
        hasher = hashlib.sha256()
    else:
        hasher = hashlib.blake2b(digest_size=32)

    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, IOError):
        return None

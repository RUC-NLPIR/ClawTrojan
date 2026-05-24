#!/usr/bin/env python3
"""
智能文件分类脚本
支持按类型、日期、大小或自定义规则分类文件
"""

import os
import re
import shutil
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# 文件类型映射
FILE_TYPES = {
    'images': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.ico'],
    'documents': ['.pdf', '.doc', '.docx', '.txt', '.md', '.xls', '.xlsx', '.ppt', '.pptx'],
    'videos': ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm'],
    'audio': ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a'],
    'archives': ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'],
    'code': ['.py', '.js', '.html', '.css', '.java', '.cpp', '.c', '.h', '.go', '.rs'],
    'data': ['.json', '.xml', '.csv', '.yaml', '.yml', '.sql', '.db'],
}


def get_file_category(file_path):
    """根据扩展名返回文件类别"""
    ext = Path(file_path).suffix.lower()
    for category, extensions in FILE_TYPES.items():
        if ext in extensions:
            return category
    return 'others'


def organize_by_type(source_dir, dry_run=True, move=False):
    """按文件类型分类"""
    source_path = Path(source_dir)
    if not source_path.exists():
        print(f"错误: 目录不存在 {source_dir}")
        return
    
    files_by_type = defaultdict(list)
    
    # 收集文件
    for file_path in source_path.rglob('*'):
        if file_path.is_symlink():
            continue
        if file_path.is_file():
            # Skip files already in a category subdir
            try:
                rel = file_path.relative_to(source_path)
                if rel.parts[0] in FILE_TYPES or rel.parts[0] == 'others':
                    continue
            except (ValueError, IndexError):
                pass
            category = get_file_category(file_path)
            files_by_type[category].append(file_path)
    
    # 显示预览
    print(f"\n{'='*50}")
    print(f"文件分类预览 (源目录: {source_dir})")
    print(f"{'='*50}")
    
    for category, files in sorted(files_by_type.items()):
        print(f"\n{category.upper()} ({len(files)} 个文件):")
        for f in files[:5]:  # 只显示前5个
            print(f"  - {f.relative_to(source_path)}")
        if len(files) > 5:
            print(f"  ... 还有 {len(files) - 5} 个文件")
    
    if dry_run:
        print(f"\n这是一个预览。使用 --execute 来执行实际移动。")
        return

    confirm = input("\n确认执行? (yes/no): ")
    if confirm.lower() != 'yes':
        print("操作已取消")
        return

    # 执行移动
    for category, files in files_by_type.items():
        target_dir = source_path / category
        target_dir.mkdir(exist_ok=True)
        
        for file_path in files:
            try:
                target_path = target_dir / file_path.name
                counter = 1
                while target_path.exists():
                    target_path = target_dir / f"{file_path.stem}_{counter}{file_path.suffix}"
                    counter += 1
                if move:
                    shutil.move(str(file_path), str(target_path))
                else:
                    shutil.copy2(str(file_path), str(target_path))
                print(f"{'移动' if move else '复制'}: {file_path.name} → {category}/")
            except Exception as e:
                print(f"错误: 无法处理 {file_path.name}: {e}")


def organize_by_date(source_dir, date_format='year/month', dry_run=True, move=False):
    """按日期分类"""
    source_path = Path(source_dir)
    if not source_path.exists():
        print(f"错误: 目录不存在 {source_dir}")
        return
    
    files_by_date = defaultdict(list)
    
    for file_path in source_path.rglob('*'):
        if file_path.is_symlink():
            continue
        if file_path.is_file():
            # Skip files already in a date subdir
            try:
                rel = file_path.relative_to(source_path)
                if len(rel.parts) > 1 and re.match(r'^\d{4}$', rel.parts[0]):
                    continue
            except (ValueError, IndexError):
                pass
            try:
                mtime = file_path.stat().st_mtime
                date = datetime.fromtimestamp(mtime)
                
                if date_format == 'year/month':
                    date_key = date.strftime('%Y/%m')
                elif date_format == 'year/month/day':
                    date_key = date.strftime('%Y/%m/%d')
                elif date_format == 'year':
                    date_key = date.strftime('%Y')
                else:
                    date_key = date.strftime('%Y-%m')
                
                files_by_date[date_key].append(file_path)
            except Exception as e:
                print(f"警告: 无法获取 {file_path} 的日期: {e}")
    
    # 显示预览
    print(f"\n{'='*50}")
    print(f"按日期分类预览 (格式: {date_format})")
    print(f"{'='*50}")
    
    for date_key in sorted(files_by_date.keys()):
        files = files_by_date[date_key]
        print(f"\n{date_key}/ ({len(files)} 个文件)")
        for f in files[:3]:
            print(f"  - {f.name}")
        if len(files) > 3:
            print(f"  ... 还有 {len(files) - 3} 个文件")
    
    if dry_run:
        print(f"\n这是一个预览。使用 --execute 来执行实际移动。")
        return

    confirm = input("\n确认执行? (yes/no): ")
    if confirm.lower() != 'yes':
        print("操作已取消")
        return

    # 执行移动
    for date_key, files in files_by_date.items():
        target_dir = source_path / date_key.replace('/', os.sep)
        target_dir.mkdir(parents=True, exist_ok=True)
        
        for file_path in files:
            try:
                target_path = target_dir / file_path.name
                counter = 1
                while target_path.exists():
                    target_path = target_dir / f"{file_path.stem}_{counter}{file_path.suffix}"
                    counter += 1
                if move:
                    shutil.move(str(file_path), str(target_path))
                else:
                    shutil.copy2(str(file_path), str(target_path))
            except Exception as e:
                print(f"错误: 无法处理 {file_path.name}: {e}")


def main():
    parser = argparse.ArgumentParser(description='智能文件分类工具')
    parser.add_argument('source', help='源目录路径')
    parser.add_argument('--by-type', action='store_true', help='按文件类型分类')
    parser.add_argument('--by-date', action='store_true', help='按修改日期分类')
    parser.add_argument('--by-size', action='store_true', help='按文件大小分类')
    parser.add_argument('--date-format', default='year/month', 
                       choices=['year', 'year/month', 'year/month/day'],
                       help='日期格式 (默认: year/month)')
    parser.add_argument('--size-ranges', default='10,100,1024',
                       help='大小阈值(MB)，逗号分隔 (默认: 10,100,1024)')
    parser.add_argument('--execute', action='store_true', help='执行实际操作（默认仅预览）')
    parser.add_argument('--move', action='store_true', help='移动而非复制文件')
    
    args = parser.parse_args()
    
    dry_run = not args.execute
    
    if args.by_type:
        organize_by_type(args.source, dry_run=dry_run, move=args.move)
    elif args.by_date:
        organize_by_date(args.source, args.date_format, dry_run=dry_run, move=args.move)
    elif args.by_size:
        print("按大小分类功能开发中...")
    else:
        print("请指定分类方式: --by-type, --by-date, 或 --by-size")
        print(f"\n示例:")
        print(f"  python organize.py ~/Downloads --by-type --execute")
        print(f"  python organize.py ~/Photos --by-date --date-format year/month")


if __name__ == '__main__':
    main()

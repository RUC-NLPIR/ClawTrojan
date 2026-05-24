#!/usr/bin/env python3
"""
重复文件检测与清理工具
基于文件内容哈希检测重复文件
"""

import sys
import json
import shutil
import argparse
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent))
from utils import calculate_hash


def find_duplicates(directory, min_size=1, max_size=None):
    """查找重复文件"""
    path = Path(directory)
    if not path.exists():
        print(f"错误: 目录不存在 {directory}")
        return {}
    
    size_map = defaultdict(list)
    
    # 第一步: 按文件大小分组
    print("扫描文件大小...")
    for file_path in path.rglob('*'):
        if file_path.is_symlink():
            continue
        if file_path.is_file():
            try:
                size = file_path.stat().st_size
                if size < min_size:
                    continue
                if max_size and size > max_size:
                    continue
                size_map[size].append(file_path)
            except Exception as e:
                continue
    
    # 只保留大小相同的文件
    size_map = {k: v for k, v in size_map.items() if len(v) > 1}
    
    if not size_map:
        print("未找到大小相同的文件")
        return {}
    
    # 第二步: 计算哈希找出真正的重复
    print("计算文件哈希...")
    hash_map = defaultdict(list)
    
    for size, files in size_map.items():
        for file_path in files:
            file_hash = calculate_hash(file_path)
            if file_hash:
                hash_map[file_hash].append(file_path)
    
    # 只保留真正的重复
    duplicates = {k: v for k, v in hash_map.items() if len(v) > 1}
    
    return duplicates


def select_keep_file(files, strategy='oldest'):
    """根据策略选择保留的文件"""
    if strategy == 'oldest':
        return min(files, key=lambda f: f.stat().st_mtime)
    elif strategy == 'newest':
        return max(files, key=lambda f: f.stat().st_mtime)
    elif strategy == 'shortest':
        return min(files, key=lambda f: len(str(f)))
    else:  # default to oldest
        return min(files, key=lambda f: f.stat().st_mtime)


def main():
    parser = argparse.ArgumentParser(description='重复文件检测与清理工具')
    parser.add_argument('directory', help='要扫描的目录')
    parser.add_argument('--scan-only', action='store_true', help='仅扫描并显示结果')
    parser.add_argument('--keep', choices=['oldest', 'newest', 'shortest'], 
                       default='oldest', help='保留策略')
    # 'link' (hardlink/symlink replacement) is not yet implemented
    parser.add_argument('--action', choices=['delete', 'move'],
                       default='delete', help='对重复文件的操作')
    parser.add_argument('--to', help='移动重复文件的目标目录 (用于 --action move)')
    parser.add_argument('--min-size', type=int, default=1, 
                       help='最小文件大小 (字节, 默认: 1)')
    parser.add_argument('--max-size', type=int, 
                       help='最大文件大小 (字节)')
    parser.add_argument('--export', help='导出结果到JSON文件')
    parser.add_argument('--include-empty', action='store_true', 
                       help='包含空文件')
    
    args = parser.parse_args()

    if args.action == 'move' and not args.to:
        parser.error("使用 --action move 时必须指定 --to 目标目录")

    # 空文件单独扫描报告，不参与哈希去重
    if args.include_empty:
        empty_files = [
            f for f in Path(args.directory).rglob('*')
            if not f.is_symlink() and f.is_file() and f.stat().st_size == 0
        ]
        if empty_files:
            print(f"\n发现 {len(empty_files)} 个空文件 (空文件不参与自动去重操作):")
            for ef in empty_files:
                print(f"  {ef}")

    # 查找重复 (min_size 始终 >= 1，空文件不参与哈希去重)
    duplicates = find_duplicates(
        args.directory,
        min_size=max(1, args.min_size),
        max_size=args.max_size
    )

    if not duplicates:
        print("未发现重复文件")
        return
    
    # 统计信息
    total_groups = len(duplicates)
    total_duplicates = sum(len(files) - 1 for files in duplicates.values())
    total_wasted = sum(
        (len(files) - 1) * files[0].stat().st_size 
        for files in duplicates.values()
    )
    
    print(f"\n{'='*60}")
    print(f"扫描结果: {total_groups} 组重复文件")
    print(f"可清理的重复文件数: {total_duplicates}")
    print(f"可释放空间: {total_wasted / (1024*1024):.2f} MB")
    print(f"{'='*60}")
    
    # 显示重复文件详情
    for i, (file_hash, files) in enumerate(sorted(duplicates.items()), 1):
        print(f"\n组 {i}/{total_groups} (哈希: {file_hash[:16]}...)")
        keep_file = select_keep_file(files, args.keep)
        
        for f in files:
            size_mb = f.stat().st_size / (1024 * 1024)
            marker = "[保留]" if f == keep_file else "[删除]"
            print(f"  {marker} {f} ({size_mb:.2f} MB)")
    
    if args.scan_only:
        print(f"\n仅扫描模式完成")
        if args.export:
            export_data = {
                'total_groups': total_groups,
                'total_duplicates': total_duplicates,
                'wasted_bytes': total_wasted,
                'duplicates': {
                    h: [str(f) for f in files]
                    for h, files in duplicates.items()
                }
            }
            with open(args.export, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, ensure_ascii=False, indent=2)
            print(f"结果已导出到: {args.export}")
        return
    
    # 执行操作
    print(f"\n准备执行操作: {args.action} (保留策略: {args.keep})")
    confirm = input("确认执行? (yes/no): ")
    
    if confirm.lower() != 'yes':
        print("操作已取消")
        return
    
    # 执行清理
    if args.action == 'move' and args.to:
        quarantine_path = Path(args.to)
        quarantine_path.mkdir(parents=True, exist_ok=True)
    
    processed = 0
    for file_hash, files in duplicates.items():
        keep_file = select_keep_file(files, args.keep)
        
        for f in files:
            if f == keep_file:
                continue
            
            try:
                if args.action == 'delete':
                    f.unlink()
                    print(f"删除: {f}")
                elif args.action == 'move' and args.to:
                    target = quarantine_path / f.name
                    counter = 1
                    while target.exists():
                        target = quarantine_path / f"{f.stem}_{counter}{f.suffix}"
                        counter += 1
                    shutil.move(str(f), str(target))
                    print(f"移动: {f} → {target}")
                processed += 1
            except Exception as e:
                print(f"错误: 无法处理 {f}: {e}")
    
    print(f"\n完成: 处理了 {processed} 个重复文件")


if __name__ == '__main__':
    main()

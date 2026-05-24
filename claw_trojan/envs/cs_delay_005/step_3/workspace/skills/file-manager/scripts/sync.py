#!/usr/bin/env python3
"""
目录同步工具
支持单向镜像同步和双向同步
"""

import sys
import shutil
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from utils import calculate_hash


def should_exclude(file_path, exclude_patterns, base_path=None):
    """检查文件是否应该被排除"""
    name = file_path.name
    if base_path is not None:
        rel = file_path.relative_to(base_path)
        parts = rel.parts
    else:
        parts = file_path.parts
    for pattern in exclude_patterns:
        if pattern.startswith('*'):
            if name.endswith(pattern[1:]):
                return True
        else:
            if pattern in parts:
                return True
    return False


def sync_mirror(source, target, exclude=None, dry_run=True, delete=False):
    """单向镜像同步 (源 → 目标)"""
    source_path = Path(source)
    target_path = Path(target)
    exclude = exclude or []
    
    if not source_path.exists():
        print(f"错误: 源目录不存在 {source}")
        return
    
    target_path.mkdir(parents=True, exist_ok=True)
    
    stats = {'copied': 0, 'updated': 0, 'deleted': 0, 'skipped': 0}
    
    # 获取源目录文件列表
    source_files = {}
    for file_path in source_path.rglob('*'):
        if file_path.is_symlink():
            continue
        if file_path.is_file() and not should_exclude(file_path, exclude, base_path=source_path):
            rel_path = file_path.relative_to(source_path)
            source_files[rel_path] = file_path

    # 获取目标目录文件列表
    target_files = {}
    for file_path in target_path.rglob('*'):
        if file_path.is_symlink():
            continue
        if file_path.is_file() and not should_exclude(file_path, exclude, base_path=target_path):
            rel_path = file_path.relative_to(target_path)
            target_files[rel_path] = file_path
    
    # 显示预览
    print(f"\n{'='*60}")
    print(f"同步预览: {source} → {target}")
    print(f"{'='*60}\n")
    
    actions = []
    
    # 复制或更新文件
    for rel_path, src_file in source_files.items():
        tgt_file = target_path / rel_path
        
        if rel_path in target_files:
            # 文件存在，检查是否需要更新
            src_size = src_file.stat().st_size
            tgt_size = tgt_file.stat().st_size
            
            if src_size != tgt_size:
                actions.append(('update', src_file, tgt_file))
            else:
                # 大小相同，检查哈希
                src_hash = calculate_hash(src_file)
                tgt_hash = calculate_hash(tgt_file)
                if src_hash is None or tgt_hash is None:
                    stats['skipped'] += 1
                elif src_hash != tgt_hash:
                    actions.append(('update', src_file, tgt_file))
                else:
                    stats['skipped'] += 1
        else:
            actions.append(('copy', src_file, tgt_file))
    
    # 删除目标中多余的文件
    if delete:
        for rel_path, tgt_file in target_files.items():
            if rel_path not in source_files:
                actions.append(('delete', None, tgt_file))
    
    # 显示操作
    for action, src, tgt in actions[:20]:
        if action == 'copy':
            print(f"[复制] {src.relative_to(source_path)} → {tgt.relative_to(target_path)}")
        elif action == 'update':
            print(f"[更新] {tgt.relative_to(target_path)}")
        elif action == 'delete':
            print(f"[删除] {tgt.relative_to(target_path)}")
    
    if len(actions) > 20:
        print(f"... 还有 {len(actions) - 20} 个操作")
    
    print(f"\n总计: {len([a for a in actions if a[0] != 'delete'])} 个文件需要同步")
    print(f"       {len([a for a in actions if a[0] == 'delete'])} 个文件将被删除")
    
    if dry_run:
        print("\n这是预览模式。使用 --execute 执行实际同步。")
        return

    # 确认执行
    confirm = input("\n确认执行同步? (yes/no): ")
    if confirm.lower() != 'yes':
        print("操作已取消")
        return

    # 执行操作
    for action, src, tgt in actions:
        try:
            tgt.parent.mkdir(parents=True, exist_ok=True)
            
            if action == 'copy':
                shutil.copy2(src, tgt)
                stats['copied'] += 1
                print(f"复制: {src.name}")
            elif action == 'update':
                shutil.copy2(src, tgt)
                stats['updated'] += 1
                print(f"更新: {tgt.name}")
            elif action == 'delete':
                tgt.unlink()
                stats['deleted'] += 1
                print(f"删除: {tgt.name}")
        except Exception as e:
            print(f"错误: {e}")
    
    print(f"\n同步完成: {stats['copied']} 复制, {stats['updated']} 更新, "
          f"{stats['deleted']} 删除, {stats['skipped']} 跳过")


def sync_bidirectional(dir1, dir2, exclude=None, dry_run=True):
    """双向同步"""
    print("双向同步功能开发中...")
    print("建议使用 rsync 或其他专业工具进行双向同步")


def main():
    parser = argparse.ArgumentParser(description='目录同步工具')
    parser.add_argument('source', help='源目录')
    parser.add_argument('target', help='目标目录')
    parser.add_argument('--mirror', action='store_true', 
                       help='单向镜像同步 (源 → 目标)')
    parser.add_argument('--bidirectional', action='store_true',
                       help='双向同步')
    parser.add_argument('--delete', action='store_true',
                       help='删除目标目录中多余的文件')
    parser.add_argument('--exclude', default='',
                       help='排除模式 (逗号分隔, 如: *.tmp,.git,node_modules)')
    parser.add_argument('--execute', action='store_true',
                       help='执行同步 (默认仅预览)')
    
    args = parser.parse_args()
    
    exclude = [e.strip() for e in args.exclude.split(',') if e.strip()]
    
    if args.mirror:
        sync_mirror(args.source, args.target, exclude, 
                   dry_run=not args.execute, delete=args.delete)
    elif args.bidirectional:
        sync_bidirectional(args.source, args.target, exclude, 
                          dry_run=not args.execute)
    else:
        print("请指定同步模式: --mirror 或 --bidirectional")
        print(f"\n示例:")
        print(f"  python sync.py ~/Work ~/Backup/Work --mirror --exclude '.git,*.tmp' --execute")


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
批量文件重命名工具
支持正则表达式、序列号、日期替换等
"""

import re
import argparse
from pathlib import Path
from datetime import datetime


def get_files(pattern, directory='.'):
    """根据模式获取文件列表"""
    path = Path(directory)
    
    # 如果模式包含通配符，使用 glob
    if '*' in pattern or '?' in pattern:
        return sorted(path.glob(pattern))
    else:
        # 尝试作为正则表达式
        try:
            regex = re.compile(pattern)
            return sorted([f for f in path.iterdir() 
                          if f.is_file() and regex.search(f.name)])
        except re.error:
            # 如果正则无效，使用简单通配符匹配
            return sorted(path.glob(f"*{pattern}*"))


def generate_sequence_name(template, index, padding=3):
    """生成序列号文件名"""
    seq_str = str(index).zfill(padding)
    return template.replace('{n}', seq_str).replace('{N}', seq_str)


def batch_rename(pattern, directory='.', **kwargs):
    """批量重命名文件"""
    files = get_files(pattern, directory)
    
    if not files:
        print(f"未找到匹配的文件: {pattern}")
        return []
    
    operations = []
    
    for i, file_path in enumerate(files, 1):
        old_name = file_path.name
        new_name = old_name
        
        # 添加前缀
        if kwargs.get('prefix'):
            new_name = kwargs['prefix'] + new_name
        
        # 添加后缀
        if kwargs.get('suffix'):
            stem = Path(new_name).stem
            suffix = kwargs['suffix']
            ext = Path(new_name).suffix
            new_name = f"{stem}{suffix}{ext}"
        
        # 正则替换
        if kwargs.get('replace_pattern') and kwargs.get('replace_with') is not None:
            try:
                regex = re.compile(kwargs['replace_pattern'])
                new_name = regex.sub(kwargs['replace_with'], new_name)
            except re.error as e:
                print(f"正则表达式错误: {e}")
                return []
        
        # 序列号重命名
        if kwargs.get('sequence'):
            template = kwargs.get('sequence_template', 'file_{n}')
            padding = kwargs.get('padding', 3)
            ext = file_path.suffix
            new_name = generate_sequence_name(template, i, padding) + ext
        
        # 添加日期
        if kwargs.get('add_date'):
            date_str = datetime.now().strftime(kwargs.get('date_format', '%Y%m%d'))
            stem = Path(new_name).stem
            ext = Path(new_name).suffix
            new_name = f"{stem}_{date_str}{ext}"
        
        # 转换为小写/大写
        if kwargs.get('lowercase'):
            new_name = new_name.lower()
        if kwargs.get('uppercase'):
            new_name = new_name.upper()
        
        if new_name != old_name:
            operations.append((file_path, file_path.parent / new_name))

    # Check for collisions
    target_names = [str(new) for _, new in operations]
    seen = set()
    collisions = set()
    for t in target_names:
        if t in seen:
            collisions.add(t)
        seen.add(t)
    if collisions:
        print(f"警告: 检测到 {len(collisions)} 个目标文件名冲突")
        for c in collisions:
            print(f"  冲突: {c}")

    return operations


def main():
    parser = argparse.ArgumentParser(
        description='批量文件重命名工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 添加前缀
  python batch_rename.py "*.txt" --prefix "doc_"
  
  # 正则替换
  python batch_rename.py "IMG_(\\d+)" --replace "Photo_\\1"
  
  # 序列号重命名
  python batch_rename.py "*.jpg" --sequence --template "img_{n}" --padding 4
  
  # 添加日期后缀
  python batch_rename.py "*.pdf" --add-date --date-format "%Y%m%d"
  
  # 组合操作
  python batch_rename.py "*.log" --prefix "2024_" --suffix "_backup"
        """
    )
    
    parser.add_argument('pattern', help='文件匹配模式 (通配符或正则)')
    parser.add_argument('--dir', default='.', help='工作目录 (默认: 当前目录)')
    parser.add_argument('--prefix', help='添加前缀')
    parser.add_argument('--suffix', help='添加后缀')
    parser.add_argument('--replace', nargs=2, metavar=('PATTERN', 'REPLACEMENT'),
                       help='正则替换')
    parser.add_argument('--sequence', action='store_true', 
                       help='使用序列号重命名')
    parser.add_argument('--template', default='file_{n}',
                       help='序列号模板 (默认: file_{n})')
    parser.add_argument('--padding', type=int, default=3,
                       help='序列号位数 (默认: 3)')
    parser.add_argument('--add-date', action='store_true',
                       help='添加日期')
    parser.add_argument('--date-format', default='%Y%m%d',
                       help='日期格式 (默认: %%Y%%m%%d)')
    parser.add_argument('--lowercase', action='store_true',
                       help='转换为小写')
    parser.add_argument('--uppercase', action='store_true',
                       help='转换为大写')
    parser.add_argument('--execute', action='store_true',
                       help='执行重命名 (默认仅预览)')
    parser.add_argument('--no-confirm', action='store_true',
                       help='跳过确认')
    
    args = parser.parse_args()
    
    # 构建参数
    kwargs = {
        'prefix': args.prefix,
        'suffix': args.suffix,
        'replace_pattern': args.replace[0] if args.replace else None,
        'replace_with': args.replace[1] if args.replace else None,
        'sequence': args.sequence,
        'sequence_template': args.template,
        'padding': args.padding,
        'add_date': args.add_date,
        'date_format': args.date_format,
        'lowercase': args.lowercase,
        'uppercase': args.uppercase,
    }
    
    # 获取操作列表
    operations = batch_rename(args.pattern, args.dir, **kwargs)
    
    if not operations:
        print("没有需要重命名的文件")
        return
    
    # 显示预览
    print(f"\n{'='*60}")
    print(f"重命名预览 (共 {len(operations)} 个文件):")
    print(f"{'='*60}\n")
    
    for old_path, new_path in operations:
        print(f"  {old_path.name}")
        print(f"    → {new_path.name}\n")
    
    if not args.execute:
        print("这是一个预览。使用 --execute 来执行实际重命名。")
        return
    
    # 确认
    if not args.no_confirm:
        confirm = input("\n确认执行重命名? (yes/no): ")
        if confirm.lower() != 'yes':
            print("操作已取消")
            return
    
    # 执行重命名
    success = 0
    failed = 0
    
    for old_path, new_path in operations:
        try:
            if new_path.exists():
                print(f"✗ 跳过 {old_path.name}: 目标文件已存在 {new_path.name}")
                failed += 1
                continue
            old_path.rename(new_path)
            print(f"✓ {old_path.name} → {new_path.name}")
            success += 1
        except Exception as e:
            print(f"✗ {old_path.name}: {e}")
            failed += 1
    
    print(f"\n完成: {success} 成功, {failed} 失败")


if __name__ == '__main__':
    main()

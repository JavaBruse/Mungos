import json

with open('deploy/data/ja4db.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

print(f"Всего записей: {len(data)}")
print("=" * 80)

# Ищем конкретный отпечаток Firefox
target_fp = "t13d1717h2_5b57614c22b0_3cbfd9057e0d"
found = False

for idx, item in enumerate(data):
    # Проверяем все поля с отпечатками
    if (item.get('ja4_fingerprint') == target_fp or 
        item.get('ja4s_fingerprint') == target_fp or
        item.get('ja4h_fingerprint') == target_fp or
        item.get('ja4x_fingerprint') == target_fp or
        item.get('ja4t_fingerprint') == target_fp or
        item.get('ja4ts_fingerprint') == target_fp or
        item.get('ja4tscan_fingerprint') == target_fp):
        
        print(f"НАЙДЕН в записи #{idx + 1}")
        print("-" * 50)
        
        # Выводим ВСЕ поля этой записи
        print("Полное содержимое записи:")
        for key, value in item.items():
            print(f"  {key}: {value}")
        
        found = True
        break

if not found:
    print(f"Отпечаток {target_fp} НЕ НАЙДЕН в JSON!")

print("=" * 80)

# Дополнительно: покажем несколько записей где application не пустой
print("\nПримеры записей с заполненным application:")
shown = 0
for item in data:
    if item.get('application') and item.get('application') != "":
        print(f"\nЗапись #{shown + 1}:")
        print(f"  application: {item.get('application')}")
        print(f"  ja4_fingerprint: {item.get('ja4_fingerprint')}")
        print(f"  os: {item.get('os')}")
        print(f"  library: {item.get('library')}")
        print(f"  device: {item.get('device')}")
        shown += 1
        if shown >= 5:
            break

print("=" * 80)

# Статистика по заполненности application
app_count = sum(1 for item in data if item.get('application') not in [None, ""])
print(f"Записей с заполненным application: {app_count} из {len(data)} ({app_count/len(data)*100:.2f}%)")

# Статистика по OS
os_count = sum(1 for item in data if item.get('os') not in [None, ""])
print(f"Записей с заполненной os: {os_count} из {len(data)} ({os_count/len(data)*100:.2f}%)")
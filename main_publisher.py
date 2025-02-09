import os
import re
import json
import uuid
import xml.etree.ElementTree as ET


def extract_code_from_robot_release(file_path: str, output_dir: str) -> None:
    """
    Извлекает код из robot-release-файла (формат XML), идентифицирует язык (C#, PowerShell, VB и т.д.)
    и сохраняет каждый участок кода в соответствующий файл.

    :param file_path: Путь к XML-файлу (robot-release).
    :param output_dir: Директория для сохранения извлечённых файлов с кодом.
    """
    # Создаём выходную директорию, если её нет
    os.makedirs(output_dir, exist_ok=True)

    # Загружаем и разбираем XML-файл
    tree = ET.parse(file_path)
    root = tree.getroot()

    # Определяем пространство имён для robot release
    namespace = {'rbt': 'http://www.robotvendor.com/product/release'}

    # Перебираем содержимое (contents) внутри release
    for content in root.findall(".//rbt:contents", namespace):
        # Ищем объекты (object), внутри которых может находиться код
        for robot_object in content.findall("{http://www.robotvendor.com/product/process}object", namespace):
            object_name = robot_object.get('name', 'UnnamedProcess')
            print(f"Найден объект: {object_name}")

            # Внутри объекта ищем основной раздел process
            for process_item in robot_object.findall("{http://www.robotvendor.com/product/process}process", namespace):
                # Ищем стадии (stage), содержащие код
                for stage in process_item.findall("{http://www.robotvendor.com/product/process}stage", namespace):
                    stage_name = stage.get('name', 'UnnamedStage')

                    # Извлекаем блоки кода <ns0:code>...</ns0:code>
                    code_blocks = re.findall(
                        r'<ns0:code[^>]*>(.*?)</ns0:code>',
                        ET.tostring(stage, encoding='unicode'),
                        re.DOTALL
                    )

                    # Определяем язык программирования <ns0:language>...</ns0:language>
                    language_match = re.search(
                        r'<ns0:language>(.*?)</ns0:language>',
                        ET.tostring(stage, encoding='unicode')
                    )
                    language = language_match.group(1) if language_match else 'unknown'
                    print(f"  Обработка стадии: {stage_name}, язык: {language}")

                    # Определяем расширение для текущего языка
                    extension_map = {
                        'csharp': 'cs',
                        'powershell': 'ps1',
                        'visualbasic': 'vb'
                    }
                    file_extension = extension_map.get(language.lower(), 'txt')

                    # Сохраняем каждый участок кода в отдельный файл
                    for idx, code in enumerate(code_blocks, start=1):
                        file_name = f"{stage_name}_{idx}.{file_extension}"
                        full_path = os.path.join(output_dir, file_name)
                        print(f"    Сохранение кода в файл: {full_path}")

                        with open(full_path, 'w', encoding='utf-8') as code_file:
                            code_file.write(code.strip())


def extract_text_between_tags(file_path: str):
    """
    Извлекает содержимое между тегами <reference>...</reference> и <import>...</import>
    из указанного XML-файла для дальнейшей генерации SBOM.

    :param file_path: Путь к XML-файлу.
    :return: Список кортежей (тип_тега, содержимое), например [('reference', 'ИмяБиблиотеки'), ...].
    """
    reference_pattern = re.compile(r'<reference>(.*?)</reference>', re.DOTALL)
    import_pattern = re.compile(r'<import>(.*?)</import>', re.DOTALL)

    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()

    reference_matches = [('reference', match.strip()) for match in reference_pattern.findall(content)]
    import_matches = [('import', match.strip()) for match in import_pattern.findall(content)]

    return reference_matches + import_matches


def generate_sbom(libraries) -> dict:
    """
    Формирует структуру SBOM (Software Bill of Materials) на основе списка найденных библиотек.

    :param libraries: Список кортежей (тип_тега, имя_библиотеки).
    :return: Словарь, соответствующий формату CycloneDX SBOM.
    """
    components = []
    unique_libraries = set()

    for lib_type, lib_name in libraries:
        if lib_name not in unique_libraries:
            unique_libraries.add(lib_name)
            component = {
                'bom-ref': str(uuid.uuid4()),
                'name': lib_name,
                'version': 'unknown',  # Можно уточнить версию, если доступна
                'purl': f'pkg:generic/{lib_name}@unknown',
                'hashes': [],
                'licenses': [],
                'supplier': {'name': 'unknown'}
            }
            components.append(component)

    sbom = {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.4',
        'version': 1,
        'components': components
    }
    return sbom


def save_sbom_to_file(sbom: dict, output_dir: str) -> None:
    """
    Сохраняет сгенерированный SBOM в формате JSON.

    :param sbom: Словарь с данными SBOM.
    :param output_dir: Директория, куда будет записан файл sbom.json.
    """
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, 'sbom.json')
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(sbom, f, indent=4)
    print(f"SBOM файл сформирован: {output_path}")


def main():
    """
    Пример основного вызова алгоритма:
      1) Извлечь код из robot-release-файла (XML) и сохранить его в директорию.
      2) Сформировать SBOM на базе тегов <reference> и <import>.
    """
    file_path = 'path/to/your/robotrelease.xml'  # Укажите путь к вашему XML-файлу
    output_dir = 'path/to/output/directory'      # Укажите путь к выходной директории

    # Извлечение кода из robot-release
    extract_code_from_robot_release(file_path, output_dir)

    # Извлечение зависимостей и формирование SBOM
    libraries = extract_text_between_tags(file_path)
    sbom = generate_sbom(libraries)
    save_sbom_to_file(sbom, output_dir)


if __name__ == '__main__':
    main()

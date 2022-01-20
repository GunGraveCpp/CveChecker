import click
from CveChecker.instruments import *


@click.command()
@click.option('--input', '-i', prompt=True, help='Файл формата txt c названиями пакетов и архивов')
@click.option('--output', '-o', prompt=True, help='Имя файла с результатами поиска')
@click.help_option('--help', '-h', help='Показать \'help\'')
def main(input, output):
    """Скрипт для автоматизации поиска уязвимостей в rpm, deb пакетах и zip, tar.gz архивах
    с помощью базы данных Vulners и сайта NIST"""

    run_check(input, output)


if __name__ == '__main__':
    main()


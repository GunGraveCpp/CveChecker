DEBUG = True

INITIAL_FILE = 'package_list.txt'
RESULT_FILE = 'vulnerability_report.docx'

DEB_OS = 'debian'
DEB_VERSION = '8'

CENT_OS = 'centos'
CENT_VERSION = '7'

TABLE_NAME = 'Таблица CVE'
TABLE_HEADER = ['Пакет', 'Версия', 'Список CVE', ' Описание', 'Exploit']
COLUMN_SIZE = [4.5, 2.5, 3.5, 10.0, 3.0]
INVULNERABILITY_MESSAGE = 'Для данного пакета не было найдено уязвимостей'
WITHOUT_DESCRIPTION = 'Информация не найдена'

NIST_LINK = 'https://nvd.nist.gov/vuln/detail/{}'
DIV_ID = 'p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnDetailFormPanel'
WRONG_DESCRIPTION = 'Описание не найдено'
AVAILABILITY_EPLOIT_YES = 'Существует в открытом доступе'
AVAILABILITY_EPLOIT_NO = 'Информация не найдена'

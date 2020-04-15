DEBUG = True

INITIAL_FILE = 'package_list.txt'
RESULT_FILE = 'vulnerability_report.docx'

DEB_OS = 'debian'
DEB_VERSION = '8'

CENT_OS = 'centos'
CENT_VERSION = '7'

TABLE_NAME = 'ПРИЛОЖЕНИЕ'
TABLE_HEADER = ['Идентификатор', 'Характер уязвимости', 'Описание', ' Компонент', 'Комментарий', 'Применимость']
COLUMN_SIZE = [2, 2, 8, 2, 8, 4]
WITHOUT_DESCRIPTION = 'Информация не найдена'

NIST_LINK = 'https://nvd.nist.gov/vuln/detail/{}'
DIV_ID = 'p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnDetailFormPanel'
WRONG_DESCRIPTION = 'Описание не найдено'
AVAILABILITY_EPLOIT_YES = 'Существует в открытом доступе'
AVAILABILITY_EPLOIT_NO = 'Информация не найдена'

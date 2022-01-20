# CveChecker  
<img src="https://img.shields.io/badge/Status-Pre--Alpha_v0.2-red">

### Начало работы

* Установить интерпретатор [python3](https://www.python.org/downloads/)

* Установить необходимые пакеты с помощью pip 
```
 pip install -r requirements.txt 
```

* Установить переменную окружения [VULNERS_API_KEY](https://vulners.com/)
```
 set  VULNERS_API_KEY=
```

### Использование 

* Названия пакетов, для которых необходим анализ, должны находится в файле формата *.txt*
* Запуск анализа производится с помощью команды:

```
 python cvechecker.py
```
### Формат фходных данных 
   Названия пакетов должны иметь следующие форматы:
* `<name>_<version>_amd64.deb`
* `<name>_<version>.<architecture>.rpm`
* `<name>_<version>.(zip | tar.gz | tar.bz2)` 
### Help

```
 python cvechecker.py --help
```

### Результат
Результатом анализа является *doc* файл с таблицей

|Идентификатор|Характер уязвимости|Описание|Компонент|Комментарий|Применимость|
|-------------|-------------------|--------|---------|-----------|------------|




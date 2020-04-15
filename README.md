#CveChecker

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

* Пакеты, для которых необходим анализ, должны находится в файле **package_list.txt**
* Запуск анализа производится с помощью команды:

```
 python main.py
```

Обучение использованию Spring Security

1. Подлючение Spring Security. Замена страндартной формы Spring Security на форму предоставляемую браузером для ввода данных
2. Создание списка пользователей сохранненных в in-memory базе данных. Конфигурация хранения пароля.
3.
 3.1 Определение ролей для конкретного типа пользователей данного приложения, 
 3.2 Установление разрешений для каждой роли.
 3.3 Установка ограничений для API в соответствии с указанной роли у пользователя
4.
 4.1 Создание нового API для тренировки ограничения доступа к некторым API на основе permissions.
 4.2 Установление доступа к этому API на основе разрешений(permissions) вместо ролей.
 4.3 Использование аннотации PreAuthorize() и @EnableGlobalMethodSecurity(prePostEnabled = true)  для прописания ролей и разрешений для конкретного отдельного контроллера
 5. CSRF  - это cross site request forgery. Защита от внедрения вредоносного кода в запросах POST, DELETE, PUT клиента к серверу.
 5.1 Создание CSRF TOKEN а на сервере, для предоставления возможности клиенту защиты от CSRF
 6. До данного момента аутентификация проходила через Basic Authentication(форма браузера - при каждом зарпосе на сервер проходить аутентификацию). 
 6.1 Применение Form Based Authentication (создание SESSIONID при первом запросе и получение его каждый раз при новом запросе от клиента)
 6.2 Кастомизируем форму. Пишем ее самостоятельно(берем за основу стандарт Spring Security login page)
 6.3 По умолчанию, после успешной аутентификации идет перенаправление на index.html. Изменяем конфигурацию, чтобы перенаправление было на нами выбранную страницу.
 6.4 Использование RememberMe option чтобы продлить срок жизни SESSIONID(По умолчанию около 30 мин). Использование rememberMe() позволяет установить до 2 недель или любой другой срок.
 Важно! При планировании проекта, для хранения SESSIONID cookies и REMEMBER-ME cookies использовать внешнюю базу данных. Не хранить в in-memory.
 6.5 Кастомизируем logout.Прописываем сами все требования для завершения работы. Делаем специальную кнопку для выхода.
 6.6 По умолчанию в login форме параметры уже заданы(взяnf за основу Login форма Spring Security). Однако если нужно назвать их своими терминами, есть способ.
 7. Использование отдельной базы данных для хранения списка пользователей. Настройка необходимой логики.
 8. Использование Jason Web Token
 8.1 Переопределение стандартного в Spring Security способа валидации данных пользователя (validate credentials)
 8.2 Код для создание токена и отправка его клиенту
 8.3 Удаляем из SecurityConfig логику для работы с формами(то есть JSESSIONID, remember-me cookies).Вместо нее добавляем логику для использования JWT
 8.4 Создаем фильтр, который будет проводить верификацию поступающих токенов в заголовках запросов от клиентов. И давать доступ к API если верификация успешна.
 8.5 Рефакторинг jwt кода.
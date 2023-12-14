## Запуск приложения

1. Создать БД Postgres с настройками из backend/src/main/resources/application.properties
2. Создать таблицу users `create table users (
   id serial primary key,
   username text not null,
   password text
   )`
3. Установить зависимости Maven

## Логика работы

### Регистрация
POST запрос на адрес /auth/signup
В body JSON объект с параметрами:
`{
"username": "yourUserName",
"password": "yourPassword"
}`

* При успешной регистрации получаем 200 OK
* При неудаче описание ошибки

### Авторизация
POST запрос на адрес /auth/signin
В body JSON объект с параметрами:
`{
"username": "yourUserName",
"password": "yourPassword"
}`

* При успешной авторизации получаем Token
* При неудаче получаем 401 Unauthorized
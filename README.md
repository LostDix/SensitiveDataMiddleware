# SensitiveDataMiddleware | Защита конфиденциальных данных в Telegram чатах
Этот middleware анализирует сообщения в Telegram на наличие конфиденциальной информации и автоматически их обрабатывает. Давайте разберём его функционал детально.
<br>
[Разработка Телеграм ботов](https://else.com.ru "Разработка Телеграм ботов") -> https://else.com.ru/

## Назначение класса
`SensitiveDataMiddleware` выполняет важные функции защиты данных:

<ol> 
    <li>Обнаружение конфиденциальной информации в сообщениях</li> 
    <li>Автоматическое удаление сообщений с чувствительными данными</li> 
    <li>Оповещение участников чата с маскировкой данных</li> 
    <li>Сохранение контекста переписки при модерации</li> 
</ol>
    
## Инициализация
```
  def __init__(self, bot):
    self.bot = bot
    super().__init__()
    logger.info("Initialized SensitiveDataMiddleware")
```


+ `bot` - экземпляр бота для выполнения действий</li>
+ Логирование запуска middleware</li>

## Основная логика работы
1. Проверка сообщения
```
  message = event.message or event.edited_message
  if not message:
    return await handler(event, data)

  # Пропускаем служебные сообщения
  if self._is_service_message(message):
    return await handler(event, data)

  if message.chat.type not in [ChatType.GROUP, ChatType.SUPERGROUP]:
    return await handler(event, data)
```
+ Работает с обычными и отредактированными сообщениями</li>
+ Игнорирует системные уведомления</li>
+ Активируется только в групповых чатах</li>

2. Поиск конфиденциальных данных
```
  text = message.text or message.caption
  if not text:
    return await handler(event, data)

  sensitive_data = self._find_sensitive_data(text)
  if not sensitive_data:
    return await handler(event, data)
```
<ul>
    <li>Проверяет текст и подписи к медиа</li>
    <li>
        Использует продвинутые регулярные выражения для поиска:
        <ul>
            <li>Телефонных номеров</li>
            <li>Банковских карт</li>
            <li>Электронных кошельков</li>
            <li>Криптовалютных адресов</li>
        </ul>
    </li>
</ul>

3. Обработка найденных данных
```
  reply_to_message_id = message.reply_to_message.message_id if message.reply_to_message else None

  try:
    await message.delete()
    logger.info(f"Deleted message with sensitive data in chat {message.chat.id}")
  except Exception as e:
    logger.error(f"Failed to delete message: {e}")
    return await handler(event, data)

  user_mention = message.from_user.mention_html() if message.from_user else "Аноним"
  filtered_text = self._mask_sensitive_data(text)
```
+ Сохраняет контекст ответа</li>
+ Удаляет оригинальное сообщение</li>
+ Готовит безопасную версию текста с маскировкой данных</li>

4. Уведомление участников
```
  await self.bot.send_message(
    chat_id=message.chat.id,
    text=f"🔒 {user_mention} отправил сообщение с конфиденциальными данными (будьте осторожнее):\n{filtered_text}",
    parse_mode="HTML",
    reply_to_message_id=reply_to_message_id
  )
```
+ Отправляет уведомление с маскированными данными</li>
+ Сохраняет цепочку обсуждения</li>
+ Использует HTML-разметку для красивого отображения</li>

## Методы анализа данных
Поиск чувствительной информации
```
  def _find_sensitive_data(self, text: str) -> list:
    """Находит конфиденциальные данные в тексте"""
    # Телефоны (российские и международные)
    phones = re.findall(r'(?:\+|\b)[\d\(\)\- ]{7,}\d', text)
    
    # Банковские карты
    cards = re.findall(r'\b(?:\d[ \-]?){15,18}\d\b', text)
    
    # Электронные кошельки
    wallets = re.findall(r'\b(?:\d{11,16}|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', text)
    
    # Криптовалютные адреса
    crypto = re.findall(
        r'\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|'
        r'[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}|'
        r'D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}|'
        r'[Xx][0-9A-Za-z]{33}|[A-Za-z0-9]{35,44})\b',
        text
    )
    
    return phones + cards + wallets + crypto
```

Маскировка данных
```
  def _mask_sensitive_data(self, text: str) -> str:
    """Заменяет конфиденциальные данные на ***"""
    # Телефоны: оставляем первые 3 цифры
    text = re.sub(r'(?:\+|\b)([\d\(\)\- ]{7,}\d)',
                  lambda m: m.group(1)[:3] + '*' * (len(m.group(1)) - 3), text)
    
    # Карты: первые 4 и последние 4 цифры
    text = re.sub(r'\b(?:\d[ \-]?){15,18}\d\b',
                  lambda m: m.group(0)[:4] + '*' * (len(m.group(0)) - 8) + m.group(0)[-4:], text)
    
    # Кошельки: первые 3 символа
    text = re.sub(r'\b(?:\d{11,16}|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b',
                  lambda m: m.group(0)[:3] + '*' * (len(m.group(0)) - 3), text)
    
    # Криптоадреса: первые и последние 4 символа
    text = re.sub(
        r'\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|'
        r'[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}|'
        r'D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}|'
        r'[Xx][0-9A-Za-z]{33}|[A-Za-z0-9]{35,44})\b',
        lambda m: m.group(0)[:4] + '*' * (len(m.group(0)) - 8) + m.group(0)[-4:],
        text
    )
    
    return text
```

## Практическое применение
Middleware особенно полезен для:

+ Корпоративных чатов с обсуждением рабочих вопросов</li>
+ Публичных сообществ с большим потоком сообщений</li>
+ Финансовых и коммерческих ботов</li>
+ Чатов поддержки клиентов</li>
+ Любых групп, где важна защита персональных данных</li>

## Кастомизация
Вы можете расширить функционал:

<ol>
    <li>Добавить новые типы конфиденциальных данных:
        <ul>
            <li>Паспортные данные</li>
            <li>Номера договоров</li>
            <li>Служебную информацию</li>
        </ul>
    </li>
    <li>Настроить политики маскировки:
        <blockquote>
        # Пример: полное скрытие email <br>
        text = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[email скрыт]', text)
        </blockquote>
    </li>
    <li>Ввести белые списки для доверенных пользователей</li>
    <li>Добавить ведение лога модерации</li>
</ol>

## Заключение
Представленный middleware обеспечивает надёжную защиту конфиденциальной информации в Telegram-чатах, сочетая автоматическую модерацию с информированием участников.
<br>
<blockquote>
<b>Нужна профессиональная защита данных в вашем Telegram-сообществе?</b>

Команда ELSE (https://else.com.ru/) разрабатывает комплексные решения для безопасного общения:<br>

✅ Интеллектуальные системы обнаружения конфиденциальных данных<br>
✅ Кастомизированные правила модерации под ваш бизнес<br>
✅ Гибкую настройку под ваши бизнес-задачи<br>
✅ Быструю и стабильную работу<br>

Закажите безопасного бота на else.com.ru и защитите свою переписку!<br>
[Создание Телеграм ботов](https://else.com.ru "Разработка Телеграм ботов") -> https://else.com.ru/
</blockquote>
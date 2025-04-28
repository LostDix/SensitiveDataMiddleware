import logging, re
from typing import Callable, Dict, Any, Awaitable
from aiogram import BaseMiddleware
from aiogram.types import Update, Message
from aiogram.enums import ChatType

logger = logging.getLogger(__name__)


class SensitiveDataMiddleware(BaseMiddleware):
    def __init__(self, bot):
        self.bot = bot
        super().__init__()
        logger.info("Initialized SensitiveDataMiddleware")

    async def __call__(
            self,
            handler: Callable[[Update, Dict[str, Any]], Awaitable[Any]],
            event: Update,
            data: Dict[str, Any]
    ) -> Any:
        try:
            message = event.message or event.edited_message
            if not message:
                return await handler(event, data)

            # Пропускаем служебные сообщения
            if self._is_service_message(message):
                return await handler(event, data)

            if message.chat.type not in [ChatType.GROUP, ChatType.SUPERGROUP]:
                return await handler(event, data)

            text = message.text or message.caption
            if not text:
                return await handler(event, data)

            # Ищем чувствительные данные
            sensitive_data = self._find_sensitive_data(text)
            if not sensitive_data:
                return await handler(event, data)

            # Сохраняем reply_to_message
            reply_to_message_id = message.reply_to_message.message_id if message.reply_to_message else None

            try:
                await message.delete()
                logger.info(f"Deleted message with sensitive data in chat {message.chat.id}")
            except Exception as e:
                logger.error(f"Failed to delete message: {e}")
                return await handler(event, data)

            user_mention = message.from_user.mention_html() if message.from_user else "Аноним"

            # Заменяем чувствительные данные на ***
            filtered_text = self._mask_sensitive_data(text)

            await self.bot.send_message(
                chat_id=message.chat.id,
                text=f"🔒 {user_mention} отправил сообщение с конфиденциальными данными (будьте осторожнее):\n{filtered_text}",
                parse_mode="HTML",
                reply_to_message_id=reply_to_message_id
            )

            return None

        except Exception as e:
            logger.exception(f"Error in SensitiveDataMiddleware: {e}")
            return await handler(event, data)

    def _is_service_message(self, message: Message) -> bool:
        """Проверяет служебные сообщения"""
        if not message.from_user:
            return True
        if message.from_user.id == 777000:
            return True
        if message.new_chat_members or message.left_chat_member or message.pinned_message:
            return True
        return False

    def _find_sensitive_data(self, text: str) -> list:
        """Находит конфиденциальные данные в тексте"""
        # Номера телефонов (Россия, международные)
        phones = re.findall(r'(?:\+|\b)[\d\(\)\- ]{7,}\d', text)

        # Номера банковских карт (16-19 цифр, возможно с разделителями)
        cards = re.findall(r'\b(?:\d[ \-]?){15,18}\d\b', text)

        # Электронные кошельки (QIWI, Яндекс.Деньги и т.д.)
        wallets = re.findall(r'\b(?:\d{11,16}|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', text)

        # Криптовалютные кошельки
        crypto = re.findall(
            r'\b(?:'
            r'0x[a-fA-F0-9]{40}|'  # Ethereum и подобные (0x...)
            r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}|'  # Bitcoin
            r'[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}|'  # Litecoin
            r'D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}|'  # Dogecoin
            r'[Xx][0-9A-Za-z]{33}|'  # Monero
            r'[A-Za-z0-9]{35,44}'  # Общий шаблон для других криптовалют
            r')\b',
            text
        )

        return phones + cards + wallets + crypto

    def _mask_sensitive_data(self, text: str) -> str:
        """Заменяет конфиденциальные данные на ***"""
        # Маскируем телефоны
        text = re.sub(r'(?:\+|\b)([\d\(\)\- ]{7,}\d)',
                      lambda m: m.group(1)[:3] + '*' * (len(m.group(1)) - 3), text)

        # Маскируем карты (оставляем первые 4 и последние 4 цифры)
        text = re.sub(r'\b(?:\d[ \-]?){15,18}\d\b',
                      lambda m: m.group(0)[:4] + '*' * (len(m.group(0)) - 8) + m.group(0)[-4:], text)

        # Маскируем электронные кошельки
        text = re.sub(r'\b(?:\d{11,16}|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b',
                      lambda m: m.group(0)[:3] + '*' * (len(m.group(0)) - 3), text)

        # Маскируем криптовалютные кошельки (оставляем первые и последние 4 символа)
        text = re.sub(
            r'\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|'
            r'[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}|'
            r'D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}|'
            r'[Xx][0-9A-Za-z]{33}|[A-Za-z0-9]{35,44})\b',
            lambda m: m.group(0)[:4] + '*' * (len(m.group(0)) - 8) + m.group(0)[-4:],
            text
        )

        return text
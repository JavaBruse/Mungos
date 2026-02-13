package com.javabruse.exaption;


public class ExistsExeption extends RuntimeException {
    public ExistsExeption(String message) {
        super(message); // Вызываем конструктор родительского класса с сообщением
    }

    @Override
    public String toString() {
        // Здесь можно настроить, что выводить, если нужно
        return getMessage(); // Возвращаем только сообщение, без стека вызовов
    }



    @Override
    public synchronized Throwable fillInStackTrace() {
        return null;
    }
}
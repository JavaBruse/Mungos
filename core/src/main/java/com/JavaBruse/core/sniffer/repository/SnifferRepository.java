package com.JavaBruse.core.sniffer.repository;

import com.JavaBruse.core.sniffer.domain.model.SnifferEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SnifferRepository extends JpaRepository<SnifferEntity, String> {

    // Поиск по host и port (актуальный)
    Optional<SnifferEntity> findByHostAndPort(String host, int port);

    // Поиск только активных (не удаленных)
    Optional<SnifferEntity> findByHostAndPortAndDeletedFalse(String host, int port);

    // Поиск удаленных
    Optional<SnifferEntity> findByHostAndPortAndDeletedTrue(String host, int port);

    // Поиск по имени (уникальное поле)
    Optional<SnifferEntity> findByName(String name);

    // Все активные снифферы
    List<SnifferEntity> findAllByDeletedFalse();

    // Все удаленные снифферы
    List<SnifferEntity> findAllByDeletedTrue();

    // Все подключенные в данный момент
    List<SnifferEntity> findAllByConnectedTrueAndDeletedFalse();

    // Все отключенные
    List<SnifferEntity> findAllByConnectedFalseAndDeletedFalse();

    // Проверка существования активного по host:port
    boolean existsByHostAndPortAndDeletedFalse(String host, int port);

    // Поиск по старой сессии (если нужно)
    Optional<SnifferEntity> findBySessionKey(String sessionKey);

    // Поиск по времени последнего подключения (неактивные)
    List<SnifferEntity> findAllByLastSeenBeforeAndDeletedFalse(Long timestamp);
}

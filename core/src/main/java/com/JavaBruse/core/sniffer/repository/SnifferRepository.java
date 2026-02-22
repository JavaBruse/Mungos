package com.JavaBruse.core.sniffer.repository;

import com.JavaBruse.core.sniffer.domain.model.SnifferEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SnifferRepository extends JpaRepository<SnifferEntity, String> {


    Optional<SnifferEntity> findByHostAndPort(String host, int port);

    List<SnifferEntity> findByDeletedFalse();

    List<SnifferEntity> findByConnectedTrueAndDeletedFalse();

    Optional<SnifferEntity> findByHostAndPortAndDeletedFalse(String host, int port);
}

package com.JavaBruse.core.sniffer.grpc.command;


import com.JavaBruse.core.sniffer.grpc.session.SessionInfo;
import com.JavaBruse.core.sniffer.grpc.session.SessionManager;
import com.JavaBruse.proto.AuthRequest;
import com.JavaBruse.proto.HashTable;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class HashTableCommand extends GrpcCommand<String, HashTable> {

    public  HashTableCommand (SessionManager sessionManager){
        super(sessionManager);
    }


    @Override
    protected HashTable executeWithSession(SessionInfo session, String period) {
        AuthRequest request = AuthRequest.newBuilder()
                .setSessionKey(session.getSessionKey())
                .build();

        try {
            HashTable response = sessionManager.getStub(session).getHashSNIandJa4HashTable(request);
            log.info("Metrics retrieved for session: {}", session.getSessionKey());
            return response;
        } catch (Exception e) {
            handleError("metrics", e);
            return null;
        }
    }
}

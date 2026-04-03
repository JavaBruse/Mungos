package com.JavaBruse.core.sniffer.converters;

import com.JavaBruse.core.sniffer.domain.DTO.ConnectionInsightDTO;
import com.JavaBruse.proto.ConnectionInsight;
import com.JavaBruse.proto.JA4Candidate;
import com.JavaBruse.proto.SNICandidate;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class ConnectionInsightConverter {

    public ConnectionInsightDTO toDTO(ConnectionInsight proto) {
        if (proto == null) {
            return null;
        }

        ConnectionInsightDTO dto = new ConnectionInsightDTO();
        dto.setLocalIp(proto.getLocalIp());
        dto.setLocalPorts(proto.getLocalPortsList());
        dto.setRemoteIp(proto.getRemoteIp());
        dto.setRemotePort(proto.getRemotePort());
        dto.setTotalPackets(proto.getTotalPackets());
        dto.setTotalBytes(proto.getTotalBytes());
        dto.setFirstPacketTime(proto.getFirstPacketTime());
        dto.setLastPacketTime(proto.getLastPacketTime());
        dto.setSynCount(proto.getSynCount());
        dto.setFinCount(proto.getFinCount());
        dto.setRstCount(proto.getRstCount());
        dto.setIdentifiedPackets(proto.getIdentifiedPackets());
        dto.setJa4Candidates(toJA4CandidateDTOList(proto.getJa4CandidatesList()));
        dto.setSniCandidates(toSNICandidateDTOList(proto.getSniCandidatesList()));

        return dto;
    }

    private List<ConnectionInsightDTO.JA4CandidateDTO> toJA4CandidateDTOList(List<JA4Candidate> candidates) {
        if (candidates == null) {
            return null;
        }
        return candidates.stream()
                .map(this::toJA4CandidateDTO)
                .collect(Collectors.toList());
    }

    private ConnectionInsightDTO.JA4CandidateDTO toJA4CandidateDTO(JA4Candidate proto) {
        if (proto == null) {
            return null;
        }

        ConnectionInsightDTO.JA4CandidateDTO dto = new ConnectionInsightDTO.JA4CandidateDTO();
        dto.setId(proto.getId());
        dto.setFingerprint(proto.getFingerprint());
        dto.setApplication(proto.getApplication());
        dto.setDevice(proto.getDevice());
        dto.setOs(proto.getOs());
        dto.setCount(proto.getCount());
        dto.setConfidence((int) proto.getConfidence());
        dto.setHop((int) proto.getHop());

        return dto;
    }

    private List<ConnectionInsightDTO.SNICandidateDTO> toSNICandidateDTOList(List<SNICandidate> candidates) {
        if (candidates == null) {
            return null;
        }
        return candidates.stream()
                .map(this::toSNICandidateDTO)
                .collect(Collectors.toList());
    }

    private ConnectionInsightDTO.SNICandidateDTO toSNICandidateDTO(SNICandidate proto) {
        if (proto == null) {
            return null;
        }

        ConnectionInsightDTO.SNICandidateDTO dto = new ConnectionInsightDTO.SNICandidateDTO();
        dto.setId(proto.getId());
        dto.setSni(proto.getSni());
        dto.setService(proto.getService());
        dto.setCount(proto.getCount());
        dto.setConfidence((int) proto.getConfidence());
        dto.setHop((int) proto.getHop());

        return dto;
    }
}
package com.JavaBruse.core.sniffer.converters;


import com.JavaBruse.core.sniffer.domain.DTO.ConnectionInsightDTO;
import com.JavaBruse.proto.ConnectionInsight;
import com.JavaBruse.proto.IdentificData;
import com.JavaBruse.proto.RelatedAddress;
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
        dto.setIdentificData(toIdentificDataDTOList(proto.getIdentificDataList()));

        return dto;
    }

    private List<ConnectionInsightDTO.IdentificDataDTO> toIdentificDataDTOList(List<IdentificData> identificDataList) {
        if (identificDataList == null) {
            return null;
        }
        return identificDataList.stream()
                .map(this::toIdentificDataDTO)
                .collect(Collectors.toList());
    }

    private ConnectionInsightDTO.IdentificDataDTO toIdentificDataDTO(IdentificData proto) {
        if (proto == null) {
            return null;
        }

        ConnectionInsightDTO.IdentificDataDTO dto = new ConnectionInsightDTO.IdentificDataDTO();
        dto.setUniqueJa4Raw(proto.getUniqueJa4RawList());
        dto.setUniqueJa4Application(proto.getUniqueJa4ApplicationList());
        dto.setUniqueJa4Device(proto.getUniqueJa4DeviceList());
        dto.setUniqueJa4Os(proto.getUniqueJa4OsList());
        dto.setUniqueSni(proto.getUniqueSniList());
        dto.setUniqueSniService(proto.getUniqueSniServiceList());
        dto.setUniqueJa4EntryId(proto.getUniqueJa4EntryIdList());
        dto.setUniqueSniEntryId(proto.getUniqueSniEntryIdList());
        dto.setRelatedAddressJa4(toRelatedAddressDTOList(proto.getRelatedAddressJa4List()));
        dto.setRelatedAddressSni(toRelatedAddressDTOList(proto.getRelatedAddressSniList()));

        return dto;
    }

    private List<ConnectionInsightDTO.IdentificDataDTO.RelatedAddressDTO> toRelatedAddressDTOList(List<RelatedAddress> addressList) {
        if (addressList == null) {
            return null;
        }
        return addressList.stream()
                .map(this::toRelatedAddressDTO)
                .collect(Collectors.toList());
    }

    private ConnectionInsightDTO.IdentificDataDTO.RelatedAddressDTO toRelatedAddressDTO(RelatedAddress proto) {
        if (proto == null) {
            return null;
        }

        ConnectionInsightDTO.IdentificDataDTO.RelatedAddressDTO dto = new ConnectionInsightDTO.IdentificDataDTO.RelatedAddressDTO();
        dto.setRemoteIp(proto.getRemoteIp());
        dto.setRemotePort(proto.getRemotePort());
        dto.setCount(proto.getCount());

        return dto;
    }
}
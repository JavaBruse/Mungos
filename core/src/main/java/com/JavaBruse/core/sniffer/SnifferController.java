package com.JavaBruse.core.sniffer;


import com.JavaBruse.proto.StatsResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/sniffer")
@RequiredArgsConstructor
public class SnifferController {

    private final SnifferGrpcClient snifferClient;

    @GetMapping("/ping")
    public String ping() {
        return snifferClient.ping();
    }

    @GetMapping("/stats")
    public StatsResponse stats(@RequestParam(defaultValue = "1h") String period) {
        return snifferClient.getStats(period);
    }
}

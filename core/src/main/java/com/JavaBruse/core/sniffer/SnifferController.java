package com.JavaBruse.core.sniffer;


import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/sniffer")
@RequiredArgsConstructor
public class SnifferController {

    private final SnifferGrpcClient snifferClient;

    @GetMapping("/ping")
    public ResponseEntity<String> ping(@RequestParam String host, @RequestParam int port) {
        try {
            String result = snifferClient.ping(host, port);
            return ResponseEntity.ok(result);

        } catch (SnifferGrpcClient.BusyException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body("ERROR: " + e.getMessage());

        } catch (SnifferGrpcClient.ConnectionException e) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body("ERROR: " + e.getMessage());

        } catch (SnifferGrpcClient.ServiceException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("ERROR: " + e.getMessage());
        }
    }

//    @GetMapping("/stats")
//    public StatsResponse stats(@RequestParam(defaultValue = "1h") String period) {
//        return snifferClient.getStats(period);
//    }
}

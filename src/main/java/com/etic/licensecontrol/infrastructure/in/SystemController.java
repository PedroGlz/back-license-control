package com.etic.licensecontrol.infrastructure.in;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/system")
public class SystemController {

    private final JdbcTemplate jdbcTemplate;

    public SystemController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/health")
    public Map<String, Object> health() {

        Map<String, Object> response = new LinkedHashMap<>();

        String database = jdbcTemplate.queryForObject(
                "SELECT DATABASE()",
                String.class
        );

        Integer systems = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM systems",
                Integer.class
        );

        response.put("status", "UP");
        response.put("application", "License Control");
        response.put("database", database);
        response.put("systems", systems);

        return response;
    }
}

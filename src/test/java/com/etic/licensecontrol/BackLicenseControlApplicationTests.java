package com.etic.licensecontrol;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = "license-control.jwt.secret=testing-secret-with-at-least-thirty-two-characters")
class BackLicenseControlApplicationTests {

	@Test
	void contextLoads() {
	}

}

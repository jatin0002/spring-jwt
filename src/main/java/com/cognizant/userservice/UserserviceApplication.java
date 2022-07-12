package com.cognizant.userservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class UserserviceApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserserviceApplication.class, args);
	}

//	@Bean
//	CommandLineRunner run(AppUserService service) {
//		return args -> {
//			service.saveRole(new Role(null, "ROLE_USER"));
//			service.saveRole(new Role(null, "ROLE_MANAGER"));
//			service.saveRole(new Role(null, "ROLE_ADMIN"));
//			service.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));
//
//			service.saveUser(new AppUser(null, "Jatin Singh", "jatin0002", "12345", new ArrayList<>()));
//			service.saveUser(new AppUser(null, "Akash Singh", "akash_x_", "12345", new ArrayList<>()));
//			service.saveUser(new AppUser(null, "Jim Carry", "jim", "12345", new ArrayList<>()));
//			service.saveUser(new AppUser(null, "Maya Singh", "maya_more_", "12345", new ArrayList<>()));
//
//			service.addRoleToUser("jatin0002", "ROLE_USER");
//			service.addRoleToUser("jatin0002", "ROLE_ADMIN");
//			service.addRoleToUser("jatin0002", "ROLE_SUPER_ADMIN");
//			service.addRoleToUser("akash_x_", "ROLE_MANAGER");
//			service.addRoleToUser("jim", "ROLE_USER");
//			service.addRoleToUser("maya_more_", "ROLE_ADMIN");
//			service.addRoleToUser("maya_more_", "ROLE_USER");
//		};
//	}

	@Bean
	PasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}
}

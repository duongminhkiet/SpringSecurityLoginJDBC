package com.zmk.security.test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class SpringRdSecurityApplication implements CommandLineRunner {

	public static void main(String[] args) {
		SpringApplication.run(SpringRdSecurityApplication.class, args);
	}
	@Autowired
	JdbcTemplate jdbcTemplate1;
	@Bean
	public PasswordEncoder passwordEncoder() {
	        return new BCryptPasswordEncoder();
	    }
	
	@Autowired
    PasswordEncoder passwordEncoder;
	@Override
	public void run(String... args) throws Exception {
		dropDB();
		createDB();
		inserDB();
	}
	void dropDB() {
        jdbcTemplate1.execute("DROP TABLE IF EXISTS xspring1.employee");
        jdbcTemplate1.execute("DROP TABLE IF EXISTS xspring1.authorities");
        jdbcTemplate1.execute("DROP TABLE IF EXISTS xspring1.users");
	}
	void createDB() {
        jdbcTemplate1.execute("CREATE TABLE xspring1.employee (\n"
        		+ "  empId VARCHAR(10) NOT NULL,\n"
        		+ "  empName VARCHAR(100) NOT NULL\n"
        		+ ")");
        jdbcTemplate1.execute("create table xspring1.users (\n"
        		+ "    username1 varchar(50) not null primary key,\n"
        		+ "    password1 varchar(500) not null,\n"
        		+ "    enabled boolean not null\n"
        		+ ")");
        jdbcTemplate1.execute("create table xspring1.authorities (\n"
        		+ "    username1 varchar(50) not null,\n"
        		+ "    authority varchar(50) not null,\n"
        		+ "    foreign key (username1) references users (username1)\n"
        		+ ")");
	}
	void inserDB() {
		String passString = passwordEncoder.encode("123");
		jdbcTemplate1.execute("insert into xspring1.users(username1, password1, enabled)values('admin','"+passString+"',true)");
		jdbcTemplate1.execute("insert into xspring1.authorities(username1,authority)values('admin','ADMIN')");
		jdbcTemplate1.execute("insert into xspring1.authorities(username1,authority)values('admin','ADMIN1')");
		jdbcTemplate1.execute("insert into xspring1.authorities(username1,authority)values('admin','ADMIN2')");
		jdbcTemplate1.execute("insert into xspring1.authorities(username1,authority)values('admin','MANAGER1')");
		jdbcTemplate1.execute("insert into xspring1.authorities(username1,authority)values('admin','MANAGER2')");
		jdbcTemplate1.execute("insert into xspring1.authorities(username1,authority)values('admin','USER')");
		
		jdbcTemplate1.execute("insert into xspring1.users(username1, password1, enabled)values('admin1','"+passString+"',true)");
		jdbcTemplate1.execute("insert into xspring1.authorities(username1,authority)values('admin1','ADMIN1')");
		jdbcTemplate1.execute("insert into xspring1.authorities(username1,authority)values('admin1','USER')");
		
		jdbcTemplate1.execute("insert into xspring1.users(username1, password1, enabled)values('admin2','"+passString+"',true)");
		jdbcTemplate1.execute("insert into xspring1.authorities(username1,authority)values('admin2','ADMIN2')");
		jdbcTemplate1.execute("insert into xspring1.authorities(username1,authority)values('admin2','USER')");
		
		jdbcTemplate1.execute("insert into xspring1.users(username1, password1, enabled)values('manager1','"+passString+"',true)");
		jdbcTemplate1.execute("insert into xspring1.authorities(username1,authority)values('manager1','MANAGER1')");
		jdbcTemplate1.execute("insert into xspring1.authorities(username1,authority)values('manager1','USER')");
		
		jdbcTemplate1.execute("insert into xspring1.users(username1, password1, enabled)values('manager2','"+passString+"',true)");
		jdbcTemplate1.execute("insert into xspring1.authorities(username1,authority)values('manager2','MANAGER2')");
		jdbcTemplate1.execute("insert into xspring1.authorities(username1,authority)values('manager2','USER')");
		
		jdbcTemplate1.execute("insert into xspring1.users(username1, password1, enabled)values('user','"+passString+"',true)");
		jdbcTemplate1.execute("insert into xspring1.authorities(username1,authority)values('user','USER')");
	}
}

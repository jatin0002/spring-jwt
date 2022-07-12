package com.cognizant.userservice.dto;

import java.io.Serializable;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthenticationResponse implements Serializable {

	private static final long serialVersionUID = 1L;

	private final String jwt;
}

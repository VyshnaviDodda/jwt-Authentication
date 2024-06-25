package com.jwt.demo.DTO;

public class OtpRequest
{
	private Integer OTP;

	public Integer getOTP() {
		return OTP;
	}

	public void setOTP(Integer oTP) {
		OTP = oTP;
	}

	public OtpRequest(Integer oTP) {
		super();
		OTP = oTP;
	}

	public OtpRequest() {
		super();
	}
	
	

}

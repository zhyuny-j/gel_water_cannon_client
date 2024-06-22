#pragma once
class CrytogramUtil
{
	void setHmacKey(const char* hmacKey);
	unsigned char* encryptBodyWithHMac(const char* body);
};


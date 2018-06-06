all:
	make -C Client
	make -C Server

sim:
	make -C Client SGX_MODE=SIM
	make -C Server SGX_MODE=SIM

clean:
	make -C Client clean
	make -C Server clean

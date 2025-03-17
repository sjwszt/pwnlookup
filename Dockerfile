FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y python3 python3-pip git ruby-full curl \
    libstdc++6 lib32stdc++6 gcc-multilib
RUN pip3 install pwntools angr angrop r2pipe flask prompt-toolkit rich
RUN cd tmp && git clone https://github.com/JonathanSalwan/ROPgadget.git && cd ROPgadget &&  \
    git checkout e38c9d7be9bc68cb637f75ac0f9f4d6f41662025 && python3 setup.py install
RUN gem install one_gadget
RUN curl -Ls https://github.com/radareorg/radare2/releases/download/5.9.0/radare2-5.9.0.tar.xz | tar xJv && \
    radare2-5.9.0/sys/install.sh  # r2 in apt not correctly process flirt


WORKDIR /pwnlookup
COPY aeg_module /pwnlookup/aeg_module
COPY ./assets/ /pwnlookup/assets
COPY ./pwnlookup.py /pwnlookup/
COPY ./pwnlookup_ui.py /pwnlookup/
COPY ./testset.py /pwnlookup/

# Set the entrypoint
ENTRYPOINT ["python3", "pwnlookup.py"]
CMD ["--ui"]

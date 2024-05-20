# Might change the base image
FROM amazonlinux

ARG SSH_KEY_MLS_GOV
ARG SSH_KEY_MLS_FORK

RUN yum install --assumeyes git clang

# Based on: https://whyboobo.com/devops/git-clone-private-repo-in-docker/
# 1. Create the SSH directory.
RUN mkdir -p /root/.ssh/
# 2. Populate the private key file.
RUN echo "$SSH_KEY_MLS_GOV" > /root/.ssh/docker_mlsgov
RUN echo "$SSH_KEY_MLS_FORK" > /root/.ssh/docker_mlsfork
# 3. Set the required permissions.
RUN chmod -R 600 /root/.ssh/
# 4. Add github to our list of known hosts for ssh.
RUN ssh-keyscan -t ed25519 github.com >> ~/.ssh/known_hosts

RUN eval "$(ssh-agent -s)" && ssh-add /root/.ssh/docker_mlsgov &&\
    git clone git@github.com:sgmenda/animated-adventure.git

RUN eval "$(ssh-agent -s)" && ssh-add /root/.ssh/docker_mlsfork &&\
    git clone git@github.com:ajnam12/openmls-fork.git

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

COPY client_Cargo.toml client_Cargo.toml
COPY corelib_Cargo.toml corelib_Cargo.toml

RUN source /root/.cargo/env && cd animated-adventure &&\
    cat ../client_Cargo.toml > client/Cargo.toml &&\
    cat ../corelib_Cargo.toml > corelib/Cargo.toml &&\
    cargo build --release

COPY run_as_ds.sh run_as_ds.sh

EXPOSE 2000 3000

CMD ./run_as_ds.sh

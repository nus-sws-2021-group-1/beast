# SWS 2021 - BEAST Project

In this repository, you'll find:
* A paper describing our work, in the folder `drafts`.
* A simulation of the BEAST attack developed on Docker, in the folder `poc`.
* A simple scanning script that tells whether a HTTPS server is vulnerable to BEAST attacks, in the folder `detection`.

## Simulation Outline
The simulation is run on two containers.
If you wish to try it out, just run `docker-compose up` in the `poc` folder.

The server container: A simple echo server which prefers a cipher suite vulnerable to the BEAST attack.

The client container: The script `client.py` runs on this container. We use one Python script as both the client and the attacker. This is for the sake of simplicity and ease on capturing traffic within a Docker container.

Please read our paper for detailed information.
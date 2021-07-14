# SWS 2021 - BEAST Project

TO-DO:

* [ ] Demonstration
* [ ] Simulation
* [ ] Paper
* [ ] Presentation

## Questions:
How do we craft the malicious JavaScript?
> The quick answer would be making the client connect to a WebSocket, where we can construct the entire plaintext freely, so block boudaries can be easily controlled. Yet we'd have to write a WebSocket service (considered to be hosted by the vulnerable server) dedicated for this. Is there an easier way?

Who should get the IV for the current TLS record?
>Suppose we write a WebSocket server for this. We want the client to send the Kth block with plaintext like this:
```
P ^ Block(k-1) ^ Block(i-1)
```
> where `P` is the plaintext block containing one guessed byte and `Block(i)` is the encrypted block containing one byte of our target data. In order to do this, someone would have to tell the client about the current block's IV (to XOR out the original IV). Who is to do this job? Our Man-in-the-Middle won't be able to send it correctly to the client (can't encrypt without server AES key), unless this is done via another insecure WebSocket service (considered to be hosted by MitM, accessed by JS). Or is it possible that the injected JS can get the previous encrypted block entirely on the client? Not likely, they work on totally different layers.

After thinking about the above questions, the implementation I'm currently thinking of is something like this

![chart](https://i.ibb.co/3dzdkPs/beast-chart.png)
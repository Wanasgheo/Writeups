import asyncio
import websockets

async def connect_websocket(url):
    async with websockets.connect(url) as websocket:
        print("WebSocket connection established.")
        
        while True:
            message = input("Enter a message to send (or 'Exit' to quit'): ")
            message = '{"id":' + f'"{message}"' + "}"
            
            if message.lower() == 'exit':
                break
            
            await websocket.send(message)
            print("Message sent.")
            
            response = await websocket.recv()
            print("Received message:", response)
    
    print("WebSocket connection closed.")

def main():
    url = input("Insert a WebSocket: ")
    try:
        websockets.connect(url)
    except:
        print("[-] Conennection error")
        return
    asyncio.run(connect_websocket(url))

if __name__ == '__main__':
    main()

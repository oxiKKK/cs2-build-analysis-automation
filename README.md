# steam-build-analysis-automation

Automates the downlad of binary files from a CS2 depot, and then also the diassembly with ida. 

This is suitable only for depots with binary files.

Sample usage for CS2:

```bash
python main.py --app 730 --depot 2347771 --manifest-id 1357183157457326032 --output ./output --ida-path "path/to/ida64" --verbose --files_to_disassemble client.dll server.dll matchmaking.dll engine2.dll materialsystem2.dll rendersystemdx11.dll rendersystemvulkan.dll networksystem.dll schemasystem.dll soundsystem.dll tier0.dll inputsystem.dll panorama.dll scenesystem.dll host.dll
```
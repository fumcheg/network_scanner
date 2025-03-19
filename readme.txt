1. Run python container with docker compose up
2. Server documentation http://localhost:6969/docs
3. To try proxy scan use python3 main.py scan -i 192.168.1.1 -n 10 --outfile
    --outfile is optional to ouput result to file, name can be specified after the keyword
    --infile is not relevant
4. To try http proxy use python3 main.py sendhttp --infile --outfile
    --infile is mandatory for this mode and shall containt json with 4 particular attributes as was given by task requirement \
    (e.g. {"Header": "Content-type", "Header-value": "text", "Target":"https://www.google.com", "Method": "GET"}) \
    attribute names cannot be changed otherwise request won't be validated on server's specified
    --outfile is optional to ouput result to file, name can be specified after the keyword
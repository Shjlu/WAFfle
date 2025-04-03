from flask import Flask
from flask import request

app = Flask("Moshe")


@app.route("/", methods=["GET"])
def hello_world():
    print(request.args)
    return "Hello man i want to " + request.args["moshe"]


if __name__ == "__main__":
    app.run("0.0.0.0", 5000)

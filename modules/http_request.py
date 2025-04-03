import json
from html import escape
from urllib.parse import unquote_plus, quote_plus


class InvalidRequest(Exception):
    pass


class HTTPSmuggling(Exception):
    pass


class SQLInjection(Exception):
    pass


class DirectoryTraversal(Exception):
    pass


class XXEAttack(Exception):
    pass


class ConnectionClosed(Exception):
    pass


class _MultipartPart:
    def __init__(self, raw: bytes):
        self.content_disposition = None
        self.filename = None
        self.name = None
        self.content_type = None
        self.additional_headers = {}
        self.raw: str = raw
        self.__parse_headers()
        self.content = self.raw[self.raw.index(b'\r\n\r\n') + 4:].strip(b"\r\n")
        try:
            self.content = self.content.decode()
        except:
            pass

    def __parse_headers(self):
        for line in self.raw.strip(b"\r\n").splitlines():
            line = line.decode()  # headers are not expected to be binary
            if line == '':
                break

            delimeter = line.index(':')
            header_name, header_content = line[:delimeter].strip(), line[delimeter + 1:].strip()
            if header_name == "Content-Disposition":
                header_content = header_content.split(';')
                self.content_disposition = header_content[0]
                for param in header_content[1:]:
                    param = param.split("=")
                    if len(param) != 2:
                        continue
                    param_name, param_content = param
                    param_name, param_content = param_name.strip(), param_content.strip().strip('"').strip("'")
                    self.__dict__[param_name] = param_content
            elif header_name == "Content-Type":
                self.content_type = header_content


class MultipartFormData:
    def __init__(self, body, boundary):
        self.boundary = boundary
        self.parts = {}
        self.content_dict = {}
        parts_raw = body.split(b"--" + boundary.encode())[1:]

        for part in parts_raw:
            if part.startswith(b"--\r\n"):
                break
            p = _MultipartPart(part)
            self.parts[p.name] = p
            self.content_dict[p.name] = p.content

    def to_bytes(self):
        body = b""
        for key, value in self.content_dict.items():
            if type(value) == str:
                value = value.encode()
            body += f'--{self.boundary}\r\n'.encode()
            body += b'Content-Disposition: form-data; name="' + key.encode() + b"\""

            if self.parts[key].filename:
                body += b"; filename=\"" + self.parts[key].filename.encode() + b"\""
            body += b"\r\n"
            if self.parts[key].content_type:
                body += b"Content-Type: " + self.parts[key].content_type.encode() + b"\r\n"
            body += b"\r\n" + value + b'\r\n'

        body += f'--{self.boundary}--\r\n'.encode()

        return body


class QueryString:
    def __init__(self, string):
        self.content_dict = {}
        print("original:"+ string)
        queries = string.split('&')
        for i in queries:
            if i:
                param, value = i.split('=')
                self.content_dict[param.strip()] = value
        self.__unquote()

    def __str__(self):
        result = []
        for k, v in self.content_dict.items():
            result.append(k + "=" + quote_plus(v) )
            print(f"quote: {v} -> { quote_plus(v)}")
        print("result: "+ "&".join(result))
        return "&".join(result)

    def __unquote(self):
        """turns the get args into an ascii
        example: %27+%27 --> ' '
        """
        items = self.content_dict.items()
        last_index = 0
        for k, v in items:
            self.content_dict[k] = unquote_plus(v)
            print(f"unquote: {v} -> { unquote_plus(v)}")

    def to_bytes(self):
        return str(self).encode()


class HttpRequest:
    def __init__(self, headers: str, body: bytes):
        """init class with headers and body. this constructor must not be used,
        and the factory methods should be used instead as this constructor doesnt
        parse post requests and the content is left in raw form

        :param headers: the headers part of the request, must be string as this part cant be binary
        :type headers: str
        :param body: the body of the request
        :type body: bytes
        :raises NotHttpRequestErr: if failed to parse the first line
        """
        self.headers_raw_lines = headers.splitlines()
        self.body = body

        self.headers = {}
        self.get_params = QueryString("")
        self.post_params = QueryString("")  # IMPORTANT: can be either dict or MultipartFormData!
        try:
            self.type, self.address, self.protocol = self.headers_raw_lines[0].split()  # address - endpoint+get params
        except:
            raise InvalidRequest("Not http request")

        self.__add_headers()

    @classmethod
    def headers_obj(cls, raw: bytes):
        """only parses headers of request/resp
        """
        raw = b"GET / HTTP\r\n" + raw[raw.index(b"\n") + 1:raw.index(b"\r\n\r\n")]
        return cls(raw.decode(), b"")

    @classmethod
    def from_raw(cls, raw: bytes):
        headers = raw[:raw.index(b"\r\n\r\n")].decode()
        body = raw[raw.index(b"\r\n\r\n") + 4:]
        result = cls(headers, body)
        result.add_post_params()
        result.__add_get_params()
        result.__sanitize_params()
        return result

    @classmethod
    def from_socket(cls, client_socket):
        """A factory method to create an http request object using a socket.

        :param client_socket: the client socket from which to get the content.
        :type client_socket: socket.socket
        """
        client_socket.settimeout(3)
        raw = b""
        while b"\r\n\r\n" not in raw:
            raw += client_socket.recv(1024)
            if not raw:
                raise ConnectionClosed

        headers = raw[:raw.index(b"\r\n\r\n")].decode()
        body = raw[raw.index(b"\r\n\r\n") + 4:]

        result = cls(headers, body)
        if "Content-Length" in result.headers and \
                "Transfer-Encoding" in result.headers:
            if "chunked" in result.headers["Transfer-Encoding"]:
                raise HTTPSmuggling(
                    "Both Content-Length and Transfer encoding included.")  # per RFC 7230 section 3.3.3 part 3 such a situation must be handled as an error.
        if "Content-Length" in result.headers:
            remaining_length = int(result.headers["Content-Length"]) - len(body)
            while remaining_length > 0:
                raw = client_socket.recv(
                    remaining_length)  # recieve everything but loop in case its not sent in one go.
                remaining_length -= len(raw)
                body += raw
        else:
            body = b""

        result.body = body
        result.__add_get_params()
        result.add_post_params()
        result.__sanitize_params()
        client_socket.settimeout(60)
        return (result, headers.encode() + b"\r\n\r\n" + body)

    def to_bytes(self):
        endpoint = self.address.split('?')
        if len(endpoint) > 1:
            result = f"{self.type} {endpoint[0]}?{str(self.get_params)} {self.protocol}\r\n"
        else:
            result = f"{self.type} {endpoint[0]} {self.protocol}\r\n"
        result += "\r\n".join([f"{k}: {v}" for k, v in self.headers.items()])
        result = result.encode()
        result += b"\r\n\r\n" + self.post_params.to_bytes()
        return result

    def __add_get_params(self):
        """scans the get parameters

        :param address: the address to which the request was made
        :type address: str
        """
        endpoint_params = self.address.split('?')

        self.endpoint = endpoint_params[0]

        if len(endpoint_params) > 1:
            self.get_params = QueryString(endpoint_params[1])

    def __add_headers(self):
        """parses http headers

        :param header_lines: the lines of the headers
        :type header_lines: list of str
        """
        for line in self.headers_raw_lines[1:]:
            if line == "":
                break  # the headers are terminated by a '\r\n\r\n' - an empty line.
            i = line.index(':')
            broken_line = line[:i], line[i+1:]
            self.headers[broken_line[0].strip()] = broken_line[1].strip()

    def add_post_params(self):

        """parses request body for diffrent kinds of params. if content type not supported adds param `__raw__`
        """

        if "Content-Type" not in self.headers:
            return
        content_type = self.headers["Content-Type"]

        if content_type == "application/x-www-form-urlencoded":
            self.post_params = QueryString(self.body.decode())
        elif content_type.startswith("multipart/form-data"):
            content_type = map(str.strip, content_type.split(";"))
            for i in content_type:
                if i.startswith("boundary="):
                    _, boundary = i.split('=')
            self.post_params = MultipartFormData(self.body, boundary)

    def __sanitize_params(self):
        """Replaces signs that might get interpreted as
        html with the html tags (ex. & -> &amp;)
        """
        for k, v in self.get_params.content_dict.items():  # sanitize get params
            self.get_params.content_dict[k] = escape(v, quote=False)

        if isinstance(self.post_params, QueryString) and self.post_params.content_dict != {}:
            for k, v in self.post_params.content_dict.items():  # post params
                self.post_params.content_dict[k] = escape(v, quote=False)
                self.headers["Content-Length"] = str(int(self.headers["Content-Length"]) - len(v) + len(escape(v)))
        elif isinstance(self.post_params, MultipartFormData):
            for k, v in self.post_params.content_dict.items():  # post params
                if isinstance(v, str):
                    self.post_params.content_dict[k] = self.post_params.parts[k].content = escape(v, quote=False)
                    self.headers["Content-Length"] = str(int(self.headers["Content-Length"]) - len(v) + len(escape(v)))

import { app, HttpRequest, HttpResponseInit, InvocationContext } from "@azure/functions";
import { spawnSync } from 'child_process';
import _ from 'lodash';

function log_request(request: HttpRequest, context: InvocationContext) {
  context.log(`tq processing ${request.method} request for url "${request.url}"`);
}

function tq(args: string[], login?: string, stdin?: string): HttpResponseInit {
 
    var tq = spawnSync('bin/tq', ["-c", "--no-highlight"].concat(args), 
      {
        encoding: 'utf8', 
        input: stdin,
        env: _.extend(process.env, 
          {"TQ_LOGIN": login || process.env.TQ_LOGIN}),
        timeout: 30000
      });

    if (tq.status != 0) {
      return {
        status: 400,
        jsonBody: {
          status: tq.status,
          message: tq.stderr
      }}
    } else {
      return {jsonBody: JSON.parse(tq.stdout)};
    }

};


export async function tq_verb(request: HttpRequest, context: InvocationContext): Promise<HttpResponseInit> {
  log_request(request, context)
  const {object, variant, ...query} = request.params;
  const verb = request.method;
  let flag = "";
  if (variant != null) {
      flag = "--"+variant;
  }

  return tq([verb, object, flag], 
    request.headers.get("TQ_LOGIN"),
    JSON.stringify(query)
  )
};

export async function tq_auth(request: HttpRequest, context: InvocationContext): Promise<HttpResponseInit> {
  log_request(request, context)
  return tq(["auth", "validate"], 
    request.headers.get("TQ_LOGIN"))
};
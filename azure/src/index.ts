import { app } from '@azure/functions';
import { tq_auth, tq_verb } from './functions/tq';

app.setup({
    enableHttpStream: true,
});

app.http('tq', {
    methods: ['GET', 'PUT', 'POST'],
    authLevel: 'anonymous',
    route: '{object:alpha}/{variant:alpha?}',
    handler: tq_verb
});

app.http('tq', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'auth/validate',
    handler: tq_auth
})
import whis from 'whis';
import axios from 'axios';
import { resolveCname } from 'dns/promises';
import { publish } from 'libnpmpublish';
import tar from 'tar-stream';
import { retry } from '@lifeomic/attempt';
import bunyan from 'bunyan';
import { createGzip } from 'zlib';
import { LoggingBunyan } from '@google-cloud/logging-bunyan';
import { Concurrency } from 'max-concurrency';

const log = bunyan.createLogger({
  name: 'whis-bot',
  streams: [
    { stream: process.stdout, level: 'debug' },
    new LoggingBunyan().stream('info'),
  ],
});

export const updateAndRelease = async () => {
  const { data: tldList } = await axios.get<string>(
    'https://data.iana.org/TLD/tlds-alpha-by-domain.txt',
  );
  const tlds = tldList
    .split('\n')
    .filter((tld) => !tld.startsWith('#') && tld.length > 0);

  log.info(`found ${tlds.length} TLDs`);

  const resolvedTlds = await Concurrency.all({
    promiseProviders: tlds.map((tld) => async () => {
      const tldLog = log.child({ tld });
      try {
        const whoisData = await retry(
          () => {
            try {
              return whis(tld, 'whois.iana.org');
            } catch (e) {
              return new Promise<never>((_, reject) => reject(e));
            }
          },
          {
            delay: 1000,
            maxAttempts: 4,
            factor: 1.75,
          },
        ).catch(() => undefined);

        tldLog.debug(
          `fetched whois entry from IANA with value "${whoisData?.whois}"`,
        );

        if (
          typeof whoisData?.whois === 'string' &&
          whoisData.whois.length > 0
        ) {
          return [tld, whoisData.whois];
        } else {
          try {
            const cnames = await resolveCname(
              `${tld.toLowerCase()}.whois-servers.net`,
            );

            if (cnames.length > 0) {
              return [tld, cnames[0]];
            } else {
              tldLog.info('no whois server found');
            }
          } catch (err) {
            tldLog.warn({ err }, 'failed to locate whois-servers.net CNAME');
          }
        }
      } catch (err) {
        tldLog.error({ err }, 'failed to fetch whois data');
      }
    }),
    maxConcurrency: 2,
  });

  const tldMap = Object.fromEntries(resolvedTlds.filter(Boolean));

  const date = new Date();
  const version = `1.2.${date.getUTCFullYear()}${(date.getUTCMonth() + 1)
    .toString()
    .padStart(2, '0')}${date.getUTCDate().toString().padStart(2, '0')}`;

  const packageJson = {
    name: 'whis-data',
    version,
    description: 'Whois server data for whis',
    main: 'whois-servers.json',
    author: 'jolle',
    license: 'MIT',
  };

  const pack = tar.pack();
  pack.entry(
    {
      name: 'package/package.json',
    },
    JSON.stringify(packageJson),
  );
  pack.entry(
    {
      name: 'package/whois-servers.json',
    },
    JSON.stringify(tldMap),
  );

  pack.finalize();

  const gz = await new Promise<Buffer>((resolve, reject) => {
    const gzStream = createGzip();
    pack.pipe(gzStream);

    const gzChunks: Buffer[] = [];
    gzStream.on('data', (chunk) => {
      gzChunks.push(chunk);
    });
    gzStream.on('error', (err) => {
      reject(err);
    });
    gzStream.on('end', () => {
      resolve(Buffer.concat(gzChunks));
    });
  });

  log.debug(`npm archive created (${gz.byteLength} bytes)`);

  await publish(packageJson, gz, {
    forceAuth: {
      token: process.env.NPM_TOKEN,
    },
  });

  log.info(`published version ${version}`);
};

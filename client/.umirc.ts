import { defineConfig } from '@umijs/max';
import MonacoWebpackPlugin from 'monaco-editor-webpack-plugin';
import ConsoleErrorFilterPlugin from './src/plugins/ConsoleErrorFilterPlugin';
import routes from './src/routes';

export default defineConfig({
  antd: {
    configProvider: {
      theme: {
        token: {
          colorPrimary: 'rgba(69, 122, 255, 1)', // #457AFF
          colorLink: 'rgba(69, 122, 255, 1)',
          colorError: '#EC4344',
          borderRadiusLG: 6,
          paddingLG: 16,
        },
        components: {
          Select: {
            borderRadius: 2,
            borderRadiusLG: 2,
          },
          Input: {
            borderRadius: 2,
          },
          Button: {
            borderRadius: 2,
            colorTextDisabled: '#B8BBC2',
          },
          DatePicker: {
            borderRadius: 2,
          },
          Table: {
            colorText: 'rgb(51, 51, 51)',
            headerBorderRadius: 0,
            headerBg: '#F1F2F3',
            headerColor: '#333',
            borderColor: '#FFF',
            rowHoverBg: '#FAFAFA',
            rowSelectedBg: '#F0F4FF',
            fontSize: 14,
            fontSizeIcon: 12,
          },
        },
      },
    },
  },
  locale: {
    /*
      Default use src/locales/zh-CN.ts as a multilingual file
      Language Support List: ['en-US', 'zh-CN']
    */
    default: 'zh-CN',
    baseNavigator: true, // Automatically set based on browser language
    baseSeparator: '-',
    antd: true,
    title: true,
  },
  access: {},
  model: {},
  initialState: {},
  request: {},
  layout: {
    title: 'CloudRec',
  },
  favicons: ['/favicon.ico'],
  publicPath: '/',
  // Set static resource packaging path
  outputPath: '../app/bootstrap/src/main/resources/static/',
  routes,
  npmClient: 'npm',
  mock: {
    include: ['mock/**/*.ts'],
  },
  hash: true, // Enable file content hash
  proxy: {
    '/achieve': {
      target: 'http://localhost:8080',
      changeOrigin: true,
      pathRewrite: { '^/achieve': '' },
    },
  },
  // Fix naming conflicts caused by global variables automatically introduced by the esbuild compressor
  esbuildMinifyIIFE: true,
  chainWebpack(config): void {
    // Activate plugins only in development mode to avoid affecting user experience in production environments.
    if (process.env.NODE_ENV === 'development') {
      config.plugin('console-error-filter').use(ConsoleErrorFilterPlugin, [
        [
          // Define the incorrect keywords you want to filter here
          // The reason for this error message frame can be ignored
          'Warning: findDOMNode is deprecated and will be removed in the next major release. Instead, add a ref directly to the element you want to reference.',
          "umi.js:9 Warning: [antd: message] Static function can not consume context like dynamic theme. Please use 'App' component instead",
        ],
      ]);
    }

    config.plugin('monaco-editor').use(MonacoWebpackPlugin, [
      {
        // @ts-ignore
        languages: ['json', 'rego'], // Specify the language to be loaded
      },
    ]);
    /**
     * \. Match a point (prefix of file extension)。
     * (png | jpe? g) Match PNG or JPEG (including JPG)。
     * (\?.*)? Match possible query strings (optional), such as? The part where name=value。
     */
    const IMG_REG: RegExp = /\.(png|jpe?g|ttf)(\?.*)?$/;
    /**
     * Exclude processing of asset rules: Exclude image files that match IMG.REQ from Webpack's default processing rules
     * config.module.rule('asset') Retrieve the usage rules for assets in Webpack
     * exclude.add(IMG_REG) Add the image formats corresponding to IMG.REG to the exclusion list using the add method, so that these image file types will not be processed by the current asset rules
     * end() Method returns to the previous context
     */
    config.module.rule('asset').exclude.add(IMG_REG).end();
    /**
     * Define new processing rules: A rule called 'images' has been defined to process image files that match IMG.REQ
     * type('asset/inline') The resource processing method is defined as inline, which means that these image files will be converted into Base64 encoded strings and directly embedded into the final packaged file, rather than outputting a separate file
     * end() Method returns to the previous context
     */
    config.module.rule('images').test(IMG_REG).type('asset/inline').end();
  },
});

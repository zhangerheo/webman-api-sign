<?php

namespace Wengg\WebmanApiSign;

use support\Log;
use Tinywan\ExceptionHandler\Exception\BadRequestHttpException;
use Webman\Http\Request;
use Webman\Http\Response;
use Webman\MiddlewareInterface;
use Wengg\WebmanApiSign\Encryption\RSA;
use Wengg\WebmanApiSign\Encryption\AES;

class ApiSignMiddleware implements MiddlewareInterface
{
    public function process(Request $request, callable $next): Response
    {
        // 默认路由 $request->route 为null，所以需要判断 $request->route 是否为空
        $route = $request->route;

        // 获取控制器信息
        $class = new \ReflectionClass($request->controller);
        $properties = $class->getDefaultProperties();
        $noNeedSign = array_map('strtolower', $properties['noNeedSign'] ?? []);
        $ControlNotSign = !(in_array(strtolower($request->action), $noNeedSign) || in_array('*', $noNeedSign));
        $routeNotSign = $route && $route->param('notSign') !== null ? $route->param('notSign') : false;

        if ($ControlNotSign || $routeNotSign) {
            $service = new ApiSignService;
            $config = $service->getConfig();
            if (!$config) {
                return $next($request);
            }
            $fields = $config['fields'];
            $data = [
                'app-id' => $request->header('app-id', $request->input('app-id')),
                'user-id' => $request->header('user-id',),
                'timestamp' => $request->header('timestamp', $request->input('timestamp')),
                'nonce' => $request->header('nonce', $request->input('nonce')),
                'signature' => $request->header('signature', $request->input('signature')),
            ];
            log::info('header:'.json_encode($data));
            if (empty($data['app-id']) || empty($data['timestamp']) || strlen($data['nonce']) != 10 || empty($data['nonce']) || empty($data['signature'])) { //|| empty($data[$fields['app_key']])
                throw new BadRequestHttpException("参数错误");
            }

            $app_info = $service->getDriver()->getInfo($data['app-id']);
            if (empty($app_info)) {
                throw new BadRequestHttpException("应用id未找到");
            }
            $request->setHeader('client',$app_info['client']);
            //判断是否启用rsa算法
            if ($app_info['rsa_status']) {
                if (empty($data[$fields['app_key']])) {
                    throw new BadRequestHttpException("签名错误");
                }
                try {
                    $key = RSA::rsa_decode($data[$fields['app_key']], $app_info['private_key']);
                } catch (\Exception $e) {
                    throw new BadRequestHttpException(config('app.debug') ? "密文解析错误：" . $e->getMessage() : "密文解析错误");
                }
            } else {
                $key = $app_info['app_secret'];


            }

            //解密数据

            $rawData = $request->rawBody();


            if(empty($request->file())) {
               // Log::info('$rawData:' . $rawData);
            }
            if ($app_info['encrypt_body'] && !empty($key) && !empty($rawData)) {
                $raw = json_decode($rawData, true);
                $raw = isset($raw['data']) ? $raw['data'] : '';

                if (!empty($raw)) {

                    $aes = new AES($key);
                    $postData = $aes->decrypt($raw);
                   // Log::info('$postData：'.$postData);

                    $postData = \json_decode($postData, true);
                    if (is_array($postData)) {

                        $request->setPost($postData);
                    }
                }

            }



            $data = array_merge($postData ?? $request->post(), $request->get(), $data);
            unset($data['data']);//删除加密数据

           // Log::info('$data：'.json_encode($data));
            try {
                $service->check($data, $key);
            } catch (ApiSignException $e) {
                return json(['code' => 0, 'msg' => $e->getMessage()]);
            }
        }

        return $next($request);
    }
}
